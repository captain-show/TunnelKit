//
//  NWConnectionSocket.swift
//  TunnelKit
//
//  Copyright (c) 2026 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//

import Foundation
import Network
import SwiftyBeaver
import TunnelKitCore

private let log = SwiftyBeaver.self

/// A `GenericSocket` implementation backed by `Network.framework`'s
/// `NWConnection`, replacing the deprecated `NWUDPSession`/`NWTCPConnection`
/// stack.
///
/// Thread-safety / `@unchecked Sendable` justification:
/// the connection is started with `start(queue:)` on the `queue` passed to
/// `observe(queue:activeTimeout:)`, and `NWConnection` delivers every handler
/// block (state, better-path, receive, send completions) on exactly that
/// queue. The active-timeout work item is scheduled on the same queue. Hence
/// every stored property below is only ever touched on that single serial
/// executor, so the confinement is total and no lock is needed. This is
/// exercised by `NWConnectionSocketTests`.
public final class NWConnectionSocket: GenericSocket, @unchecked Sendable {

    /// The underlying connection, exposed so a matching `LinkInterface` can be
    /// produced on top of it.
    public let connection: NWConnection

    /// `true` for stream (TCP) transports, `false` for datagram (UDP).
    public let isReliable: Bool

    private let endpoint: NWEndpoint

    private let parameters: NWParameters

    private let remoteHost: String

    /// The remote port, exposed so a matching `LinkInterface` can label itself.
    public let remotePort: UInt16

    // MARK: State (confined to `queue`)

    private var isActive = false

    private var isReady = false

    public private(set) var isShutdown = false

    /// Set once the connect-timeout fires, so a late `.ready` cannot activate
    /// a socket the tunnel has already given up on. Does not suppress the
    /// shutdown callback (the provider still cancels and expects it).
    private var didTimeout = false

    private var activeTimeoutWorkItem: DispatchWorkItem?

    /// The queue every handler is delivered on, kept so the connect deadline can
    /// be rescheduled from within a handler.
    private var observedQueue: DispatchQueue?

    /// The connect deadline is extended at most once for an unavailable path, so
    /// a genuinely offline device still fails in bounded time.
    private var didExtendForUnavailablePath = false

    private var waitingError: NWError?

    private var lastViability: Bool?

    private var hasBetterPathFlag = false

    public weak var delegate: GenericSocketDelegate?

    public init(endpoint: NWEndpoint, parameters: NWParameters, isReliable: Bool, remoteHost: String, remotePort: UInt16) {
        self.endpoint = endpoint
        self.parameters = parameters
        self.isReliable = isReliable
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        connection = NWConnection(to: endpoint, using: parameters)
    }

    // MARK: GenericSocket

    public var remoteAddress: String? {
        remoteHost
    }

    public var remoteProtocol: String? {
        "\(isReliable ? "TCP" : "UDP"):\(remotePort)"
    }

    public var hasBetterPath: Bool {
        hasBetterPathFlag
    }

    public func observe(queue: DispatchQueue, activeTimeout: Int) {
        isActive = false
        isReady = false
        isShutdown = false
        didTimeout = false
        waitingError = nil
        lastViability = nil

        connection.stateUpdateHandler = { [weak self] state in
            // delivered on `queue`
            self?.handleState(state)
        }
        connection.betterPathUpdateHandler = { [weak self] hasBetterPath in
            self?.handleBetterPath(hasBetterPath)
        }
        connection.viabilityUpdateHandler = { [weak self] isViable in
            self?.handleViability(isViable)
        }

        observedQueue = queue
        didExtendForUnavailablePath = false

        scheduleActiveTimeout(queue: queue, milliseconds: activeTimeout)

        connection.start(queue: queue)
    }

    /// Retains a cancellable work item so readiness/unobserve prevents a stale
    /// timeout from racing a later state transition.
    private func scheduleActiveTimeout(queue: DispatchQueue?, milliseconds: Int) {
        guard let queue else {
            return
        }
        activeTimeoutWorkItem?.cancel()
        let timeoutWorkItem = DispatchWorkItem { [weak self] in
            self?.handleActiveTimeout(milliseconds: milliseconds)
        }
        activeTimeoutWorkItem = timeoutWorkItem
        queue.asyncAfter(
            deadline: .now() + .milliseconds(max(0, milliseconds)),
            execute: timeoutWorkItem
        )
    }

    /// Whether the connection is only waiting for a usable network path, which
    /// `NWConnection` recovers from by itself.
    func isPathUnavailable(_ error: NWError) -> Bool {
        guard case .posix(let code) = error else {
            return false
        }
        switch code {
        case .ENETDOWN, .ENETUNREACH, .EHOSTDOWN, .EHOSTUNREACH:
            return true

        default:
            return false
        }
    }

    public func unobserve() {
        activeTimeoutWorkItem?.cancel()
        activeTimeoutWorkItem = nil
        connection.stateUpdateHandler = nil
        connection.betterPathUpdateHandler = nil
        connection.viabilityUpdateHandler = nil
    }

    public func shutdown() {
        // cancel() drives the connection to .cancelled, reported once via
        // handleState as a non-failure shutdown
        connection.cancel()
    }

    public func upgraded() -> GenericSocket? {
        guard hasBetterPathFlag else {
            return nil
        }
        // NWConnection has no direct "upgrade" constructor; rebuild an
        // equivalent connection to the same endpoint, which the framework will
        // route over the currently-better path.
        return NWConnectionSocket(
            endpoint: endpoint,
            parameters: parameters,
            isReliable: isReliable,
            remoteHost: remoteHost,
            remotePort: remotePort
        )
    }

    // MARK: State handling (queue)

    private func handleState(_ state: NWConnection.State) {
        switch state {
        case .setup, .preparing:
            log.debug("Socket state: \(state) (\(remoteHost.maskedDescription))")

        case .waiting(let error):
            // IMPORTANT: .waiting means the connection cannot proceed right now
            // (e.g. no route, refused). It must NOT be treated as connected.
            // The connect-timeout scheduled in observe() will fail the attempt
            // if this state persists.
            waitingError = error
            isReady = false

            // An established socket falling back to `.waiting` is a dead link
            // that reports nothing else, so this has to be visible without debug
            // logging enabled.
            if isActive {
                log.warning("Socket went back to waiting while active: \(error)")
            } else {
                log.debug("Socket state: waiting (\(error))")
            }

            if isActive, lastViability != false {
                handleViability(false)
            }

        case .ready:
            // ignore a readiness that arrives after we already timed out
            guard !didTimeout, !isShutdown else {
                return
            }
            isReady = true
            waitingError = nil
            activateIfReadyAndViable()

        case .failed(let error):
            guard !isShutdown else {
                return
            }
            isShutdown = true
            activeTimeoutWorkItem?.cancel()
            activeTimeoutWorkItem = nil
            log.error("Socket failed: \(error)")
            delegate?.socket(
                self,
                didShutdownWith: connectionError(from: error, timedOut: false)
            )

        case .cancelled:
            guard !isShutdown else {
                return
            }
            isShutdown = true
            activeTimeoutWorkItem?.cancel()
            activeTimeoutWorkItem = nil
            log.debug("Socket cancelled")
            delegate?.socket(self, didShutdownWith: nil)

        @unknown default:
            log.warning("Socket state: unknown")
        }
    }

    private func handleBetterPath(_ hasBetterPath: Bool) {
        hasBetterPathFlag = hasBetterPath
        guard hasBetterPath else {
            return
        }
        log.debug("Socket has a better path")
        delegate?.socketHasBetterPath(self)
    }

    private func handleViability(_ isViable: Bool) {
        guard lastViability != isViable else {
            return
        }
        let wasActive = isActive
        lastViability = isViable
        guard !isShutdown, !didTimeout else {
            return
        }
        if isViable {
            activateIfReadyAndViable()
        }
        guard wasActive else {
            return
        }
        log.debug("Socket viability changed: \(isViable)")
        delegate?.socket(self, didUpdateViability: isViable)
    }

    private func activateIfReadyAndViable() {
        guard isReady,
              !isActive,
              lastViability != false,
              !isShutdown,
              !didTimeout else {
            return
        }
        isActive = true
        activeTimeoutWorkItem?.cancel()
        activeTimeoutWorkItem = nil
        log.debug("Socket is ready and viable (\(remoteHost.maskedDescription))")
        delegate?.socketDidBecomeActive(self)
    }

    private func handleActiveTimeout(milliseconds: Int) {
        guard !isActive, !isShutdown, !didTimeout else {
            return
        }

        // A tunnel extension that has just been restarted races the teardown of
        // the previous utun: for the first seconds there is no usable route, so
        // the connection parks in `.waiting(ENETDOWN)`. `NWConnection` recovers
        // from that on its own — it is retrying, not wedged — but the connect
        // deadline used to cut it off, burning a whole attempt plus the
        // reconnection delay on every restart. Grant it one more window instead.
        if let waitingError, isPathUnavailable(waitingError), !didExtendForUnavailablePath {
            didExtendForUnavailablePath = true
            log.warning("No usable path yet (\(waitingError)), extending the connect deadline by \(milliseconds) ms")
            scheduleActiveTimeout(queue: observedQueue, milliseconds: milliseconds)
            return
        }

        didTimeout = true
        activeTimeoutWorkItem = nil

        let error: ConnectionError
        if let waitingError {
            error = connectionError(from: waitingError, timedOut: true)
        } else {
            error = ConnectionError(
                .connectionTimeout,
                stage: .socketConnection,
                diagnostics: ["transport": isReliable ? "tcp" : "udp"]
            )
        }
        log.debug("Socket did not become active within \(milliseconds) ms")
        delegate?.socket(self, didTimeoutWith: error)

        // A timed-out NWConnection must not keep retrying in `.waiting`, and a
        // late `.ready` is already fenced by `didTimeout`.
        connection.cancel()
    }

    private func connectionError(from error: NWError, timedOut: Bool) -> ConnectionError {
        let code: ConnectionError.Code
        switch error {
        case .posix(let posixCode):
            switch posixCode {
            case .ECONNREFUSED:
                code = .connectionRefused

            case .ENETDOWN, .ENETUNREACH, .EHOSTDOWN, .EHOSTUNREACH:
                code = .networkUnavailable

            case .ETIMEDOUT:
                code = .connectionTimeout

            default:
                code = timedOut ? .connectionTimeout : (isActive ? .connectionLost : .serverUnreachable)
            }

        case .dns:
            code = .dnsFailure

        case .tls:
            code = timedOut ? .connectionTimeout : .serverUnreachable

        case .wifiAware:
            code = timedOut ? .connectionTimeout : (isActive ? .connectionLost : .serverUnreachable)

        @unknown default:
            code = timedOut ? .connectionTimeout : (isActive ? .connectionLost : .serverUnreachable)
        }
        return ConnectionError(
            code,
            stage: isActive ? .monitoring : .socketConnection,
            underlying: error,
            diagnostics: ["transport": isReliable ? "tcp" : "udp"]
        )
    }
}

extension NWConnectionSocket: CustomStringConvertible {
    public var description: String {
        "\(remoteHost.maskedDescription):\(remotePort)"
    }
}
