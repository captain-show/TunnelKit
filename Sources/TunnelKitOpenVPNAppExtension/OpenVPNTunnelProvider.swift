//
//  OpenVPNTunnelProvider.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 2/1/17.
//  Copyright (c) 2024 Davide De Rosa. All rights reserved.
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
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

import NetworkExtension
import SwiftyBeaver
#if os(iOS)
import SystemConfiguration.CaptiveNetwork
#elseif os(macOS)
import CoreWLAN
#endif
import TunnelKitCore
import TunnelKitOpenVPNCore
import TunnelKitManager
import TunnelKitOpenVPNManager
import TunnelKitOpenVPNProtocol
import TunnelKitAppExtension
import CTunnelKitCore
import __TunnelKitUtils

private let log = SwiftyBeaver.self

private func socketsAreIdentical(_ first: GenericSocket?, _ second: GenericSocket) -> Bool {
    guard let first else {
        return false
    }
    return (first as AnyObject) === (second as AnyObject)
}

private final class UncheckedSendableSocketBox: @unchecked Sendable {
    let value: GenericSocket?

    init(_ value: GenericSocket?) {
        self.value = value
    }
}

private final class UncheckedSendableCallbackBox<Callback>: @unchecked Sendable {
    let callback: Callback

    init(_ callback: Callback) {
        self.callback = callback
    }
}

/**
 Provides an all-in-one `NEPacketTunnelProvider` implementation for use in a
 Packet Tunnel Provider extension both on iOS and macOS.
 */
/// `@unchecked Sendable`: like `WireGuardTunnelProvider`, this is a
/// system-instantiated `NEPacketTunnelProvider` subclass that cannot be an
/// actor. Thread-safety comes from confining all mutable state to `tunnelQueue`
/// (the session, socket, pending handlers, flags and data-count loop are all
/// touched there); `startTunnel`/`stopTunnel` bridge in from the NE queue via a
/// `tunnelQueue.sync`/`async` hand-off. `stateMachine` is internally thread-safe.
open class OpenVPNTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    // MARK: Tweaks

    /// An optional string describing host app version on tunnel start.
    public var appVersion: String?

    /// The log separator between sessions.
    public var logSeparator = "--- EOF ---"

    /// The maximum size of the log.
    public var maxLogSize = 20000

    /// The log level when `OpenVPNTunnelProvider.Configuration.shouldDebug` is enabled.
    public var debugLogLevel: SwiftyBeaver.Level = .debug

    /// The number of milliseconds after which a DNS resolution fails.
    public var dnsTimeout = 3000

    /// The number of milliseconds after which the tunnel gives up on a connection attempt.
    public var socketTimeout = 5000

    /// The number of milliseconds after which the tunnel is shut down forcibly.
    public var shutdownTimeout = 2000

    /// The number of milliseconds after which a reconnection attempt is issued.
    public var reconnectionDelay = 1000

    /// The number of link failures after which the tunnel is expected to die.
    public var maxLinkFailures = 3

    /// Seconds between end-to-end checks after the tunnel was validated.
    /// Set to 0 to disable runtime monitoring explicitly.
    public var connectivityWatchdogInterval: TimeInterval = 15

    /// Seconds a runtime validation failure may persist before reconnecting.
    public var connectivityFailureGracePeriod: TimeInterval = 15

    /// The number of milliseconds between data count updates. Set to 0 to disable updates (default).
    public var dataCountInterval = 0

    /// A list of public DNS servers to use as fallback when none are provided (defaults to CloudFlare).
    public var fallbackDNSServers = [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
    ]

    // MARK: Constants

    private let tunnelQueue = DispatchQueue(label: OpenVPNTunnelProvider.description(), qos: .utility)

    /// Framework callbacks run away from `tunnelQueue` so synchronous client
    /// re-entry into start/stop cannot deadlock the lifecycle queue.
    private let completionQueue = DispatchQueue(
        label: "\(OpenVPNTunnelProvider.description()).completions",
        qos: .utility
    )

    private let prngSeedLength = 64

    private var cachesURL: URL? {
        let appGroup = cfg.appGroup
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            log.error("No access to app group: \(appGroup)")
            return nil
        }
        return containerURL.appendingPathComponent("Library/Caches/")
    }

    // MARK: Tunnel configuration

    private var cfg: OpenVPN.ProviderConfiguration!

    private var strategy: ConnectionStrategy!

    // MARK: Internal state

    /// Deterministic connection lifecycle; gates "connected" and neutralizes
    /// late callbacks from superseded attempts.
    private let stateMachine = ConnectionStateMachine()

    private var session: OpenVPNSession?

    private var socket: GenericSocket?

    private var pendingStartHandler: ((Error?) -> Void)?

    private var pendingStopHandlers: [() -> Void] = []

    private var validationTask: Task<Void, Never>?

    private let continuousClock = ContinuousClock()

    private var monitoringFailureSince: ContinuousClock.Instant?

    /// Attempt currently owning asynchronous DNS, socket, settings and
    /// validation callbacks. Every reconnect gets a fresh token.
    private var activeAttempt: ConnectionAttemptToken = 0

    private var socketAttempt: ConnectionAttemptToken?

    private var finalizedSocketAttempt: ConnectionAttemptToken?

    private var disposalAttempt: ConnectionAttemptToken?

    private var pendingSocketError: Error?

    private var pendingUpgradedSocket: GenericSocket?

    private var consecutiveLinkFailures = 0

    private var isCountingData = false

    private var loggingDestinations: [BaseDestination] = []

    // MARK: NEPacketTunnelProvider (XPC queue)

    open override var reasserting: Bool {
        didSet {
            log.debug("Reasserting flag \(reasserting ? "set" : "cleared")")
        }
    }

    open override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let immediateError = tunnelQueue.sync {
            self.prepareTunnelStart(completionHandler: completionHandler)
        }
        if let immediateError {
            completionHandler(immediateError)
        }
    }

    /// Runs entirely on `tunnelQueue`, making admission, preparation and the
    /// resource commit atomic with respect to stop and duplicate start calls.
    private func prepareTunnelStart(completionHandler: @escaping (Error?) -> Void) -> Error? {
        guard pendingStopHandlers.isEmpty,
              stateMachine.state != .disconnecting else {
            return ConnectionError(
                .cancelled,
                stage: .preparing,
                message: "The OpenVPN tunnel is still stopping."
            )
        }
        guard pendingStartHandler == nil else {
            return ConnectionError(
                .cancelled,
                stage: .preparing,
                message: "An OpenVPN start is already in progress."
            )
        }
        switch stateMachine.state {
        case .idle, .disconnected, .failed:
            break

        case .preparing, .connecting, .negotiating, .validating, .connected, .disconnecting:
            return ConnectionError(
                .cancelled,
                stage: .preparing,
                message: "The OpenVPN tunnel is already active."
            )
        }

        let attempt = stateMachine.startNewAttempt(initialState: .preparing)
        activeAttempt = attempt
        validationTask?.cancel()
        validationTask = nil
        monitoringFailureSince = nil
        socket?.delegate = nil
        socket?.unobserve()
        socket?.shutdown()
        socket = nil
        socketAttempt = nil
        finalizedSocketAttempt = nil
        disposalAttempt = nil
        session?.cleanup()
        session?.delegate = nil
        session = nil
        pendingUpgradedSocket = nil
        pendingSocketError = nil
        consecutiveLinkFailures = 0
        stopDataCountLoop()
        reasserting = false
        strategy = nil
        cfg = nil
        loggingDestinations.forEach { log.removeDestination($0) }
        loggingDestinations.removeAll()

        // required configuration
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw ConfigurationError.parameter(name: "protocolConfiguration")
            }
            guard let _ = tunnelProtocol.serverAddress else {
                throw ConfigurationError.parameter(name: "protocolConfiguration.serverAddress")
            }
            guard let providerConfiguration = tunnelProtocol.providerConfiguration else {
                throw ConfigurationError.parameter(name: "protocolConfiguration.providerConfiguration")
            }
            cfg = try fromDictionary(OpenVPN.ProviderConfiguration.self, providerConfiguration)
        } catch let cfgError as ConfigurationError {
            let name: String
            switch cfgError {
            case .parameter(let parameterName):
                name = parameterName
            }
            NSLog("Tunnel configuration incomplete: \(name)")
            let connectionError = ConnectionError(
                .invalidConfiguration,
                stage: .preparing,
                message: "The OpenVPN provider configuration is missing a required field.",
                underlying: cfgError,
                diagnostics: ["parameter": name]
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            return connectionError
        } catch {
            NSLog("Unexpected error in tunnel configuration: \(error)")
            let connectionError = ConnectionError(
                .invalidConfiguration,
                stage: .preparing,
                message: "The OpenVPN provider configuration could not be decoded.",
                underlying: error
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            return connectionError
        }

        // prepare for logging (append)
        configureLogging()
        cfg._appexSetLastError(nil)

        if let validationError = encryptedDNSValidationError() {
            stateMachine.transition(to: .failed, attempt: attempt)
            setErrorStatus(with: validationError)
            return validationError
        }

        // logging only ACTIVE from now on
        log.info("")
        log.info(logSeparator)
        log.info("")

        // override library configuration
        CoreConfiguration.masksPrivateData = cfg.masksPrivateData
        if let versionIdentifier = cfg.versionIdentifier {
            CoreConfiguration.versionIdentifier = versionIdentifier
        }

        // optional credentials
        let credentials: OpenVPN.Credentials?
        if let username = protocolConfiguration.username, let passwordReference = protocolConfiguration.passwordReference {
            let password: String
            do {
                password = try Keychain.password(forReference: passwordReference)
            } catch {
                // Preserve the underlying Keychain cause and distinguish a
                // user-dismissed prompt (retryable) from a missing/unusable item
                // (needs re-provisioning), instead of collapsing every failure
                // into a bare permissionDenied.
                let code: ConnectionError.Code
                var diagnostics = ["operation": "readPassword"]
                if case TunnelKitManagerError.keychain(let keychainError) = error {
                    diagnostics["keychain"] = String(describing: keychainError)
                    switch keychainError {
                    case .userCancelled:
                        code = .permissionDenied

                    case .notFound, .typeMismatch, .add:
                        code = .invalidConfiguration
                    }
                } else {
                    code = .permissionDenied
                }
                let connectionError = ConnectionError(
                    code,
                    stage: .preparing,
                    message: "The VPN password could not be read from the Keychain.",
                    underlying: error,
                    diagnostics: diagnostics
                )
                stateMachine.transition(to: .failed, attempt: attempt)
                setErrorStatus(with: connectionError)
                return connectionError
            }
            credentials = OpenVPN.Credentials(username, password)
        } else {
            credentials = nil
        }

        log.info("Starting tunnel...")

        guard OpenVPN.prepareRandomNumberGenerator(seedLength: prngSeedLength) else {
            let error = ConnectionError(
                .internalError,
                stage: .preparing,
                message: "The cryptographic random-number generator could not be initialized."
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            setErrorStatus(with: error)
            return error
        }

        if let appVersion = appVersion {
            log.info("App version: \(appVersion)")
        }
        cfg.print()

        // prepare to pick endpoints
        guard let strategy = ConnectionStrategy(configuration: cfg.configuration) else {
            let error = ConnectionError(
                .invalidConfiguration,
                stage: .preparing,
                message: "Configuration has no remotes."
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            setErrorStatus(with: error)
            return error
        }
        self.strategy = strategy

        guard let cachesURL = cachesURL else {
            let error = ConnectionError(
                .permissionDenied,
                stage: .preparing,
                message: "The packet tunnel cannot access its configured app group."
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            setErrorStatus(with: error)
            return error
        }

        let session: OpenVPNSession
        do {
            session = try OpenVPNSession(queue: tunnelQueue, configuration: cfg.configuration, cachesURL: cachesURL)
        } catch {
            let connectionError = ConnectionError(
                .invalidConfiguration,
                stage: .preparing,
                message: "The OpenVPN session could not be initialized from the configuration.",
                underlying: error
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            setErrorStatus(with: connectionError)
            return connectionError
        }
        session.credentials = credentials
        session.delegate = self

        logCurrentSSID()

        self.session = session
        activeAttempt = attempt
        socketAttempt = nil
        finalizedSocketAttempt = nil
        disposalAttempt = nil
        pendingSocketError = nil
        pendingUpgradedSocket = nil
        consecutiveLinkFailures = 0
        pendingStartHandler = completionHandler
        connectTunnel(initialAttempt: attempt)
        return nil
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("Stopping tunnel (reason: \(reason.rawValue))...")

        // all mutable state is confined to the tunnel queue
        tunnelQueue.sync {
            self.cfg?._appexSetLastError(nil)
            guard self.pendingStopHandlers.isEmpty else {
                self.pendingStopHandlers.append(completionHandler)
                return
            }
            self.pendingStopHandlers.append(completionHandler)
            let stopAttempt = self.stateMachine.beginAttempt()
            self.activeAttempt = stopAttempt
            // Retag the currently-owned socket so the orderly stop remains
            // current while every earlier callback is invalidated.
            if self.socket != nil {
                self.socketAttempt = stopAttempt
            }
            self.finalizedSocketAttempt = nil
            self.disposalAttempt = nil
            self.pendingSocketError = nil
            self.pendingUpgradedSocket = nil
            self.stateMachine.transition(to: .disconnecting, attempt: stopAttempt)
            self.validationTask?.cancel()
            self.validationTask = nil

            if let startHandler = self.pendingStartHandler {
                self.pendingStartHandler = nil
                self.dispatchStartCompletion(
                    startHandler,
                    error: ConnectionError(.cancelled, stage: .disconnection)
                )
            }

            guard let session = self.session else {
                self.stateMachine.transition(to: .disconnected, attempt: stopAttempt)
                self.reasserting = false
                self.flushLog()
                self.completeStopHandlers()
                self.forceExitOnMac()
                return
            }

            guard self.socket != nil else {
                session.cleanup()
                session.delegate = nil
                self.session = nil
                self.disposeTunnel(error: nil, attempt: stopAttempt, delay: 0)
                return
            }
            self.tunnelQueue.schedule(after: .milliseconds(self.shutdownTimeout)) { [weak self] in
                guard let self,
                      self.stateMachine.isCurrent(stopAttempt),
                      !self.pendingStopHandlers.isEmpty else {
                    return
                }
                log.warning("Tunnel not responding after \(self.shutdownTimeout) milliseconds, forcing stop")
                self.validationTask?.cancel()
                self.validationTask = nil
                self.socket?.delegate = nil
                self.socket?.unobserve()
                self.socket?.shutdown()
                self.socket = nil
                self.socketAttempt = nil
                self.session?.cleanup()
                self.session?.delegate = nil
                self.session = nil
                self.disposeTunnel(error: nil, attempt: stopAttempt, delay: 0)
            }
            session.shutdown(error: nil)
        }
    }

    // MARK: Wake/Sleep (debugging placeholders)

    open override func wake() {
        log.verbose("Wake signal received")
    }

    open override func sleep(completionHandler: @escaping () -> Void) {
        log.verbose("Sleep signal received")
        completionHandler()
    }

    // MARK: Connection (tunnel queue)

    private func connectTunnel(
        upgradedSocket: GenericSocket? = nil,
        initialAttempt: ConnectionAttemptToken? = nil
    ) {
        let attempt: ConnectionAttemptToken
        if let initialAttempt {
            guard stateMachine.isCurrent(initialAttempt) else {
                return
            }
            attempt = initialAttempt
        } else {
            attempt = stateMachine.beginAttempt()
        }
        activeAttempt = attempt
        socketAttempt = nil
        finalizedSocketAttempt = nil
        disposalAttempt = nil
        pendingSocketError = nil

        log.info("Creating link session")
        guard stateMachine.transition(to: .connecting, attempt: attempt).isAccepted else {
            log.warning("Cannot start connection attempt from state \(stateMachine.state.rawValue)")
            return
        }

        // reuse upgraded socket
        if let upgradedSocket = upgradedSocket, !upgradedSocket.isShutdown {
            log.debug("Socket follows a path upgrade")
            connectTunnel(via: upgradedSocket, attempt: attempt)
            return
        }

        strategy.createSocket(timeout: dnsTimeout, queue: tunnelQueue) { [weak self] result in
            guard let self,
                  self.stateMachine.isCurrent(attempt),
                  self.activeAttempt == attempt else {
                log.warning("Ignoring socket creation result of a superseded attempt")
                return
            }
            switch result {
            case .success(let socket):
                self.connectTunnel(via: socket, attempt: attempt)

            case .failure(let error):
                if error.code == .dnsFailure, self.strategy.tryNextEndpoint() {
                    self.connectTunnel()
                    return
                }
                self.disposeTunnel(error: error, attempt: attempt)
            }
        }
    }

    private func connectTunnel(via socket: GenericSocket, attempt: ConnectionAttemptToken) {
        guard stateMachine.isCurrent(attempt), activeAttempt == attempt else {
            socket.shutdown()
            return
        }
        log.info("Will connect to \(socket)")

        log.debug("Socket type is \(type(of: socket))")
        var activeSocket = socket
        activeSocket.delegate = self
        self.socket = activeSocket
        socketAttempt = attempt
        finalizedSocketAttempt = nil
        pendingSocketError = nil
        pendingUpgradedSocket = nil
        activeSocket.observe(queue: tunnelQueue, activeTimeout: socketTimeout)
    }

    private func finishSocketAttempt(
        socket finishingSocket: GenericSocket?,
        error: Error?,
        shouldReconnect: Bool,
        shouldAdvanceEndpoint: Bool = false,
        countsAsLinkFailure: Bool = false,
        attempt: ConnectionAttemptToken
    ) {
        guard stateMachine.isCurrent(attempt),
              activeAttempt == attempt,
              finalizedSocketAttempt != attempt else {
            return
        }
        if let finishingSocket {
            guard socketsAreIdentical(socket, finishingSocket), socketAttempt == attempt else {
                log.warning("Ignoring terminal event from an outdated socket")
                return
            }
        }
        finalizedSocketAttempt = attempt
        validationTask?.cancel()
        validationTask = nil
        let wasEstablished = pendingStartHandler == nil

        var reconnect = shouldReconnect && stateMachine.state != .disconnecting
        if reconnect && countsAsLinkFailure {
            consecutiveLinkFailures += 1
            if maxLinkFailures > 0, consecutiveLinkFailures >= maxLinkFailures {
                log.error("Reached the maximum number of consecutive link failures (\(maxLinkFailures))")
                reconnect = false
            }
        }

        var finalError = normalizedConnectionError(error)
        if reconnect && shouldAdvanceEndpoint && !strategy.tryNextEndpoint() {
            reconnect = false
            finalError = ConnectionError(
                .serverUnreachable,
                stage: .socketConnection,
                message: "All configured remote endpoints were exhausted.",
                underlying: error
            )
        }

        if let session, !(reconnect && session.canRebindLink()) {
            session.cleanup()
        }
        if !reconnect {
            session?.delegate = nil
            session = nil
        }

        let upgradedSocket = reconnect && error as? OpenVPNError == nil
            ? pendingUpgradedSocket
            : nil
        pendingUpgradedSocket = nil

        if var ownedSocket = socket {
            ownedSocket.delegate = nil
            ownedSocket.unobserve()
            if !ownedSocket.isShutdown {
                ownedSocket.shutdown()
            }
        }
        socket = nil
        socketAttempt = nil
        pendingSocketError = nil

        isCountingData = false
        refreshDataCount()

        if let finalError {
            log.error("Tunnel did stop (error: \(finalError))")
            if reconnect {
                setErrorStatus(with: finalError)
            }
        } else {
            log.info("Tunnel did stop on request")
        }

        guard reconnect else {
            let isOrderlyStop = !pendingStopHandlers.isEmpty || stateMachine.state == .disconnecting
            if wasEstablished && !isOrderlyStop {
                reasserting = true
            }
            disposeTunnel(
                error: isOrderlyStop ? nil : finalError,
                attempt: attempt,
                delay: (isOrderlyStop || wasEstablished) ? 0 : nil
            )
            return
        }

        if wasEstablished {
            reasserting = true
        }
        log.debug("Disconnection is recoverable, tunnel will reconnect in \(reconnectionDelay) milliseconds...")
        let upgradedSocketBox = UncheckedSendableSocketBox(upgradedSocket)
        tunnelQueue.asyncAfter(deadline: .now() + .milliseconds(reconnectionDelay)) { [weak self] in
            guard let self,
                  self.stateMachine.isCurrent(attempt),
                  self.activeAttempt == attempt,
                  self.finalizedSocketAttempt == attempt,
                  self.pendingStopHandlers.isEmpty else {
                return
            }
            log.debug("Tunnel is about to reconnect...")
            self.connectTunnel(upgradedSocket: upgradedSocketBox.value)
        }
    }

    private func disposeTunnel(
        error: Error?,
        attempt: ConnectionAttemptToken,
        delay: Int? = nil
    ) {
        guard stateMachine.isCurrent(attempt), disposalAttempt != attempt else {
            return
        }
        disposalAttempt = attempt
        let finalError = normalizedConnectionError(error)
        if socket == nil, session != nil {
            session?.cleanup()
            session?.delegate = nil
            session = nil
        }
        if let finalError {
            setErrorStatus(with: finalError)
            stateMachine.transition(to: .failed, attempt: attempt)
        } else {
            stateMachine.transition(to: .disconnected, attempt: attempt)
        }

        let disposalDelay = delay ?? reconnectionDelay
        log.info("Dispose tunnel in \(disposalDelay) milliseconds...")
        tunnelQueue.asyncAfter(deadline: .now() + .milliseconds(disposalDelay)) { [weak self] in
            guard let self,
                  self.stateMachine.isCurrent(attempt),
                  self.disposalAttempt == attempt else {
                return
            }
            self.reallyDisposeTunnel(error: finalError)
        }
    }

    private func reallyDisposeTunnel(error: Error?) {
        reasserting = false
        stopDataCountLoop()
        flushLog()

        // failed to start
        if pendingStartHandler != nil {

            //
            // CAUTION
            //
            // passing nil to this callback will result in an extremely undesired situation,
            // because NetworkExtension would interpret it as "successfully connected to VPN"
            //
            // if we end up here disposing the tunnel with a pending start handled, we are
            // 100% sure that something wrong happened while starting the tunnel. in such
            // case, here we then must also make sure that an error object is ALWAYS
            // provided, so we use a stable detailed transport error as fallback
            //
            // A transport timeout makes sense, given that any other error would normally
            // come from OpenVPN.stopError. Other paths to disposeTunnel() are only coming
            // from stopTunnel(), in which case we don't need to feed an error parameter to
            // the stop completion handler
            //
            let startHandler = pendingStartHandler
            pendingStartHandler = nil
            dispatchStartCompletion(startHandler, error: error ?? ConnectionError(
                .connectionTimeout,
                stage: .socketConnection,
                message: "The OpenVPN start ended before the transport became usable."
            ))
        }
        // stopped intentionally
        else if !pendingStopHandlers.isEmpty {
            completeStopHandlers()
            forceExitOnMac()
        }
        // stopped externally, unrecoverable
        else {
            cancelTunnelWithError(error)
            forceExitOnMac()
        }
    }

    private func completeStopHandlers() {
        let handlers = pendingStopHandlers
        pendingStopHandlers.removeAll()
        let callbacks = UncheckedSendableCallbackBox(handlers)
        completionQueue.async {
            callbacks.callback.forEach { $0() }
        }
    }

    private func dispatchStartCompletion(_ handler: ((Error?) -> Void)?, error: Error?) {
        guard let handler else {
            return
        }
        let callback = UncheckedSendableCallbackBox(handler)
        completionQueue.async {
            callback.callback(error)
        }
    }

    // MARK: Data counter (tunnel queue)

    private var isDataCountLoopRunning = false

    private var dataCountLoopGeneration: UInt64 = 0

    private func stopDataCountLoop() {
        dataCountLoopGeneration &+= 1
        isDataCountLoopRunning = false
        isCountingData = false
        cfg?._appexSetDataCount(nil)
    }

    private func refreshDataCount() {
        guard dataCountInterval > 0 else {
            dataCountLoopGeneration &+= 1
            isDataCountLoopRunning = false
            cfg?._appexSetDataCount(nil)
            return
        }
        // a single self-perpetuating publishing loop per process; repeated
        // start/stop cycles must not stack additional chains
        if !isDataCountLoopRunning {
            isDataCountLoopRunning = true
            dataCountLoopGeneration &+= 1
            scheduleDataCountLoop(generation: dataCountLoopGeneration)
        }
        publishDataCount()
    }

    private func scheduleDataCountLoop(generation: UInt64) {
        guard dataCountInterval > 0 else {
            isDataCountLoopRunning = false
            return
        }
        tunnelQueue.schedule(after: .milliseconds(dataCountInterval)) { [weak self] in
            guard let self,
                  self.isDataCountLoopRunning,
                  self.dataCountLoopGeneration == generation else {
                return
            }
            self.publishDataCount()
            self.scheduleDataCountLoop(generation: generation)
        }
    }

    private func publishDataCount() {
        guard isCountingData, let session = session, let dataCount = session.dataCount() else {
            cfg?._appexSetDataCount(nil)
            return
        }
        cfg?._appexSetDataCount(dataCount)
    }
}

extension OpenVPNTunnelProvider: GenericSocketDelegate {

    // MARK: GenericSocketDelegate (tunnel queue)

    public func socketDidTimeout(_ socket: GenericSocket) {
        self.socket(
            socket,
            didTimeoutWith: ConnectionError(.connectionTimeout, stage: .socketConnection)
        )
    }

    public func socket(_ socket: GenericSocket, didTimeoutWith error: Error) {
        guard let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt,
              socketsAreIdentical(self.socket, socket) else {
            return
        }
        log.debug("Socket timed out waiting for activity, cancelling...")
        let shouldAdvanceEndpoint = Self.shouldAdvanceEndpoint(after: error)
        finishSocketAttempt(
            socket: socket,
            error: error,
            shouldReconnect: true,
            shouldAdvanceEndpoint: shouldAdvanceEndpoint,
            countsAsLinkFailure: !shouldAdvanceEndpoint,
            attempt: attempt
        )
    }

    public func socketDidBecomeActive(_ socket: GenericSocket) {
        guard let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt,
              socketsAreIdentical(self.socket, socket),
              let session else {
            return
        }
        guard let producer = socket as? LinkProducer else {
            finishSocketAttempt(
                socket: socket,
                error: ConnectionError(
                    .internalError,
                    stage: .socketConnection,
                    message: "The active socket cannot produce an OpenVPN link."
                ),
                shouldReconnect: false,
                attempt: attempt
            )
            return
        }
        guard stateMachine.transition(to: .negotiating, attempt: attempt).isAccepted else {
            log.warning("Ignoring socket readiness in state \(stateMachine.state.rawValue)")
            return
        }
        if session.canRebindLink() {
            session.rebindLink(producer.link(userObject: cfg.configuration.xorMethod))
        } else {
            session.setLink(producer.link(userObject: cfg.configuration.xorMethod))
        }
    }

    public func socket(_ socket: GenericSocket, didShutdownWithFailure failure: Bool) {
        self.socket(
            socket,
            didShutdownWith: failure ? ConnectionError(.connectionLost, stage: .monitoring) : nil
        )
    }

    public func socket(_ socket: GenericSocket, didShutdownWith error: Error?) {
        guard let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt,
              socketsAreIdentical(self.socket, socket) else {
            return
        }
        if stateMachine.state == .connected {
            reasserting = true
        }
        pendingSocketError = error

        // Link read and socket-state handlers are both delivered on the same
        // queue. Defer one turn so a session stop already in flight wins and
        // supplies its more specific protocol/validation error.
        let eventSocket = UncheckedSendableSocketBox(socket)
        tunnelQueue.async { [weak self] in
            guard let self, let socket = eventSocket.value,
                  self.stateMachine.isCurrent(attempt),
                  self.activeAttempt == attempt,
                  socketsAreIdentical(self.socket, socket),
                  self.finalizedSocketAttempt != attempt else {
                return
            }
            if self.session?.isStopping == true {
                return
            }
            let finalError = self.session?.stopError ?? self.pendingSocketError
            if finalError as? OpenVPNError == nil {
                self.pendingUpgradedSocket = socket.upgraded() ?? self.pendingUpgradedSocket
            }
            let shouldAdvanceEndpoint = Self.shouldAdvanceEndpoint(after: finalError)
            self.finishSocketAttempt(
                socket: socket,
                error: finalError,
                shouldReconnect: finalError != nil,
                shouldAdvanceEndpoint: shouldAdvanceEndpoint,
                countsAsLinkFailure: finalError != nil && !shouldAdvanceEndpoint,
                attempt: attempt
            )
        }
    }

    public func socket(_ socket: GenericSocket, didUpdateViability isViable: Bool) {
        guard let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt,
              socketsAreIdentical(self.socket, socket) else {
            return
        }

        // Viability is ADVISORY ONLY and must never tear down a connected
        // tunnel. Inside a packet-tunnel provider, the raw NWConnection to the
        // VPN server re-evaluates its path as non-viable right after we install
        // our own default route into the utun, even though the socket keeps
        // carrying traffic. Reconnecting on that signal tears the tunnel down
        // ~2s after connect and loops forever. The pre-NWConnection transports
        // (NWUDPSession/NWTCPConnection) exposed no viability signal at all, so
        // a connected tunnel was never torn down this way. Genuine transport
        // failures still surface through the socket's `.failed`/`.cancelled`
        // state (didShutdownWith) and the OpenVPN ping timeout, which remain the
        // only teardown triggers — matching the original behavior.
        log.debug("Transport viability changed (advisory, no reconnect): \(isViable)")
    }

    public func socketHasBetterPath(_ socket: GenericSocket) {
        guard let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt,
              socketsAreIdentical(self.socket, socket),
              [.negotiating, .validating, .connected].contains(stateMachine.state) else {
            return
        }

        // `betterPath` is advisory. In a packet-tunnel provider the newly
        // installed utun can itself appear as a better route. Reconnecting
        // immediately then creates another NWConnection that reports the same
        // route, resulting in an endless disconnect/connect loop. Preserve an
        // upgrade candidate and use it only if the current transport actually
        // loses viability or shuts down.
        log.debug("Transport has a better path; deferring migration until the current path fails")
        logCurrentSSID()
        pendingUpgradedSocket = socket.upgraded()
    }
}

extension OpenVPNTunnelProvider: OpenVPNSessionDelegate {

    // MARK: OpenVPNSessionDelegate (tunnel queue)

    public func sessionWillStop(
        _ stoppingSession: OpenVPNSession,
        withError error: Error?,
        shouldReconnect: Bool
    ) {
        guard session === stoppingSession,
              let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt else {
            return
        }
        guard stateMachine.state == .connected else {
            return
        }
        reasserting = true
        if let detailedError = normalizedConnectionError(error) {
            setErrorStatus(with: detailedError)
        }
        log.info("Session is stopping (will reconnect: \(shouldReconnect))")
    }

    public func sessionDidStart(_ session: OpenVPNSession, remoteAddress: String, remoteProtocol: String?, options: OpenVPN.Configuration) {
        guard self.session === session,
              let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt else {
            log.warning("Ignoring sessionDidStart from a superseded session or attempt")
            return
        }
        log.info("Session did start (handshake complete)")
        log.info("\tAddress: \(remoteAddress.maskedDescription)")
        if let proto = remoteProtocol {
            log.info("\tProtocol: \(proto)")
        }

        guard stateMachine.transition(to: .validating, attempt: attempt).isAccepted else {
            log.warning("Ignoring sessionDidStart in state \(stateMachine.state.rawValue) (late or duplicate callback)")
            return
        }

        log.info("Local options:")
        cfg.configuration.print(isLocal: true)
        log.info("Remote options:")
        options.print(isLocal: false)

        cfg._appexSetServerConfiguration(session.serverConfiguration() as? OpenVPN.Configuration)

        log.info("Stage: applying network settings")
        let blocksIPv6 = NetworkSettingsBuilder(
            remoteAddress: remoteAddress,
            localOptions: session.configuration,
            remoteOptions: options,
            fallbackDNSServers: fallbackDNSServers
        ).blocksIPv6
        bringNetworkUp(remoteAddress: remoteAddress, localOptions: session.configuration, remoteOptions: options) { (error) in

            // hop from XPC/system queue back to the tunnel queue
            self.tunnelQueue.async {
                guard self.stateMachine.isCurrent(attempt),
                      self.activeAttempt == attempt,
                      self.socketAttempt == attempt,
                      self.session === session else {
                    log.warning("Ignoring network settings result of a superseded attempt")
                    return
                }

                if let error = error {
                    log.error("Failed to configure tunnel: \(error)")
                    self.session?.shutdown(error: ConnectionError(
                        .tunnelSetupFailed,
                        stage: .applyingNetworkSettings,
                        underlying: error
                    ))
                    return
                }

                log.info("Tunnel interface is now UP")
                let networkInterface = NETunnelInterface(impl: self.packetFlow)
                if blocksIPv6 {
                    session.setTunnel(tunnel: IPv6BlockingTunnelInterface(wrapping: networkInterface))
                } else {
                    session.setTunnel(tunnel: networkInterface)
                }
                self.beginValidation(
                    session: session,
                    remoteAddress: remoteAddress,
                    remoteOptions: options,
                    attempt: attempt
                )
            }
        }

        isCountingData = true
        refreshDataCount()
    }

    // MARK: Validation (tunnel queue)

    private func beginValidation(
        session: OpenVPNSession,
        remoteAddress: String,
        remoteOptions: OpenVPN.Configuration,
        attempt: ConnectionAttemptToken
    ) {
        // Validation is opt-in: an unset policy must NOT tear down a tunnel the
        // OS reports as connected. A synthetic probe can false-fail on a healthy
        // server (blocked ICMP/DNS, no pushed DNS), and treating that as fatal
        // drives a connect→shutdown→reconnect loop. Apps opt into `.default`/
        // `.strict` explicitly when they want end-to-end verification.
        let options = cfg.connectionValidation ?? .disabled
        guard options.isEnabled else {
            log.info("Stage: validation skipped (disabled)")
            declareConnected(attempt: attempt)
            return
        }

        log.info("Stage: validating connection")
        let settingsBuilder = NetworkSettingsBuilder(
            remoteAddress: remoteAddress,
            localOptions: cfg.configuration,
            remoteOptions: remoteOptions,
            fallbackDNSServers: fallbackDNSServers
        )
        let dnsServers = settingsBuilder.effectiveDNSServers
        let context = ConnectionValidationContext(
            localIPv4: remoteOptions.ipv4?.address,
            gatewayIPv4: remoteOptions.ipv4?.defaultGateway,
            dnsServers: dnsServers,
            localIPv6: remoteOptions.ipv6?.address,
            gatewayIPv6: remoteOptions.ipv6?.defaultGateway
        )
        let validator = ConnectionValidator(options: options, transport: session)

        validationTask?.cancel()
        let box = WeakProviderBox(self)
        let queue = tunnelQueue
        validationTask = Task {
            let outcome = await validator.validate(context: context)
            queue.async {
                box.provider?.handleValidationOutcome(
                    outcome,
                    session: session,
                    context: context,
                    options: options,
                    attempt: attempt
                )
            }
        }
    }

    private func handleValidationOutcome(
        _ outcome: ConnectionValidator.Outcome,
        session: OpenVPNSession,
        context: ConnectionValidationContext,
        options: ConnectionValidationOptions,
        attempt: ConnectionAttemptToken
    ) {
        // validationTask is niled by sessionDidStop/stopTunnel the moment the
        // attempt is superseded; if it is already nil, this outcome is stale
        // (e.g. a reconnect fired while validation was in flight) and must not
        // touch shouldReconnect or trigger a second shutdown
        guard validationTask != nil else {
            log.warning("Ignoring validation outcome: validation was already cancelled")
            return
        }
        guard stateMachine.isCurrent(attempt),
              stateMachine.state == .validating,
              self.session === session else {
            log.warning("Ignoring validation outcome of a superseded attempt (state: \(stateMachine.state.rawValue))")
            return
        }
        validationTask = nil

        switch outcome {
        case .passed(let evidence):
            log.info("Stage: validation passed (evidence: \(evidence.joined(separator: ", ")))")
            monitoringFailureSince = nil
            declareConnected(attempt: attempt)
            scheduleConnectivityWatchdog(
                session: session,
                context: context,
                options: options,
                attempt: attempt
            )

        case .passedUnverified(let reason):
            let error = ConnectionError(
                .validationFailed,
                stage: .validation,
                message: "Connectivity validation completed without end-to-end evidence.",
                diagnostics: ["reason": reason]
            )
            log.error("Stage: validation returned no evidence (\(reason))")
            setErrorStatus(with: error)
            session.shutdown(error: error)

        case .skipped:
            log.info("Stage: validation skipped")
            declareConnected(attempt: attempt)
            scheduleConnectivityWatchdog(
                session: session,
                context: context,
                options: options,
                attempt: attempt
            )

        case .cancelled:
            log.info("Stage: validation cancelled")

        case .failed(let error):
            log.error("Stage: validation FAILED (\(error))")
            setErrorStatus(with: error)
            session.shutdown(error: error)
        }
    }

    private func scheduleConnectivityWatchdog(
        session: OpenVPNSession,
        context: ConnectionValidationContext,
        options: ConnectionValidationOptions,
        attempt: ConnectionAttemptToken,
        after delay: TimeInterval? = nil
    ) {
        let configuredInterval = delay ?? connectivityWatchdogInterval
        guard options.isEnabled,
              configuredInterval.isFinite,
              configuredInterval > 0,
              stateMachine.isCurrent(attempt),
              stateMachine.state == .connected,
              self.session === session else {
            return
        }

        validationTask?.cancel()
        let validator = ConnectionValidator(options: options, transport: session)
        let box = WeakProviderBox(self)
        let queue = tunnelQueue
        let clock = continuousClock
        validationTask = Task {
            do {
                try await Task.sleep(for: .seconds(configuredInterval))
            } catch {
                return
            }
            guard !Task.isCancelled else {
                return
            }
            let validationStartedAt = clock.now
            let outcome = await validator.validate(context: context)
            queue.async {
                box.provider?.handleConnectivityWatchdogOutcome(
                    outcome,
                    session: session,
                    context: context,
                    options: options,
                    validationStartedAt: validationStartedAt,
                    attempt: attempt
                )
            }
        }
    }

    private func handleConnectivityWatchdogOutcome(
        _ outcome: ConnectionValidator.Outcome,
        session: OpenVPNSession,
        context: ConnectionValidationContext,
        options: ConnectionValidationOptions,
        validationStartedAt: ContinuousClock.Instant,
        attempt: ConnectionAttemptToken
    ) {
        guard validationTask != nil,
              stateMachine.isCurrent(attempt),
              stateMachine.state == .connected,
              self.session === session,
              !session.isStopping else {
            return
        }
        validationTask = nil

        switch outcome {
        case .passed(let evidence):
            log.info("Connectivity watchdog passed (evidence: \(evidence.joined(separator: ", ")))")
            monitoringFailureSince = nil
            reasserting = false
            cfg._appexSetLastError(nil)
            scheduleConnectivityWatchdog(
                session: session,
                context: context,
                options: options,
                attempt: attempt
            )

        case .skipped:
            monitoringFailureSince = nil
            reasserting = false
            cfg._appexSetLastError(nil)
            scheduleConnectivityWatchdog(
                session: session,
                context: context,
                options: options,
                attempt: attempt
            )

        case .passedUnverified(let reason):
            recordConnectivityWatchdogFailure(
                ConnectionError(
                    .validationFailed,
                    stage: .monitoring,
                    message: "Runtime connectivity validation produced no end-to-end evidence.",
                    diagnostics: ["reason": reason]
                ),
                session: session,
                context: context,
                options: options,
                validationStartedAt: validationStartedAt,
                attempt: attempt
            )

        case .failed(let error):
            recordConnectivityWatchdogFailure(
                ConnectionError(
                    .connectionLost,
                    stage: .monitoring,
                    message: error.message,
                    underlying: error,
                    diagnostics: error.diagnostics
                ),
                session: session,
                context: context,
                options: options,
                validationStartedAt: validationStartedAt,
                attempt: attempt
            )

        case .cancelled:
            break
        }
    }

    private func recordConnectivityWatchdogFailure(
        _ error: ConnectionError,
        session: OpenVPNSession,
        context: ConnectionValidationContext,
        options: ConnectionValidationOptions,
        validationStartedAt: ContinuousClock.Instant,
        attempt: ConnectionAttemptToken
    ) {
        let now = continuousClock.now
        if monitoringFailureSince == nil {
            monitoringFailureSince = validationStartedAt
        }

        let failureDuration = (monitoringFailureSince ?? now).duration(to: now)
        let failureDurationSeconds = timeInterval(for: failureDuration)
        let configuredGracePeriod = connectivityFailureGracePeriod
        let gracePeriod = configuredGracePeriod.isFinite ? max(0, configuredGracePeriod) : 0
        let currentError = ConnectionError(
            .connectionLost,
            stage: .monitoring,
            message: error.message,
            underlying: error,
            diagnostics: error.diagnostics.merging([
                "failureDuration": "\(failureDurationSeconds)",
                "gracePeriod": "\(gracePeriod)"
            ]) { current, _ in current }
        )
        guard failureDuration < .seconds(gracePeriod) else {
            // Only a failure that survived the grace period changes the
            // externally visible NEVPN status. A single lost probe must not
            // make a healthy tunnel flap connected -> reasserting -> connected.
            reasserting = true
            setErrorStatus(with: currentError)
            log.error("Connectivity watchdog failed: \(currentError)")
            session.reconnect(error: currentError)
            return
        }

        let validationBudget = options.maxDuration.isFinite ? max(0, options.maxDuration) : 0
        let remainingGracePeriod = max(0, gracePeriod - failureDurationSeconds)
        let watchdogInterval = connectivityWatchdogInterval.isFinite
            ? max(0.1, connectivityWatchdogInterval)
            : 1
        let minimumRetryDelay = min(watchdogInterval, 1)
        let retryDelay = min(
            watchdogInterval,
            max(minimumRetryDelay, remainingGracePeriod - validationBudget)
        )
        log.warning("Connectivity watchdog failed; rechecking during the transient-failure grace period")
        scheduleConnectivityWatchdog(
            session: session,
            context: context,
            options: options,
            attempt: attempt,
            after: retryDelay
        )
    }

    private func timeInterval(for duration: Duration) -> TimeInterval {
        let components = duration.components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1e18
    }

    private func declareConnected(attempt: ConnectionAttemptToken) {
        guard stateMachine.transition(to: .connected, attempt: attempt).isAccepted else {
            log.warning("Cannot declare connected from state \(stateMachine.state.rawValue)")
            return
        }
        log.info("Stage: connected")
        consecutiveLinkFailures = 0
        reasserting = false
        cfg._appexSetLastError(nil)
        let startHandler = pendingStartHandler
        pendingStartHandler = nil
        dispatchStartCompletion(startHandler, error: nil)
    }

    public func sessionDidStop(_ stoppedSession: OpenVPNSession, withError error: Error?, shouldReconnect: Bool) {
        guard session === stoppedSession,
              let attempt = socketAttempt,
              stateMachine.isCurrent(attempt),
              activeAttempt == attempt else {
            log.warning("Ignoring sessionDidStop from a superseded session or attempt")
            return
        }
        cfg._appexSetServerConfiguration(nil)

        if let error = error {
            log.error("Session did stop with error: \(error)")
        } else {
            log.info("Session did stop")
        }

        validationTask?.cancel()
        validationTask = nil

        isCountingData = false
        refreshDataCount()

        let finalError = error ?? pendingSocketError
        let shouldAdvanceEndpoint = Self.shouldAdvanceEndpoint(after: finalError)

        finishSocketAttempt(
            socket: socket,
            error: finalError,
            shouldReconnect: shouldReconnect,
            shouldAdvanceEndpoint: shouldAdvanceEndpoint,
            countsAsLinkFailure: (finalError as? ConnectionError).map {
                !shouldAdvanceEndpoint && ($0.code == .connectionLost || $0.code == .networkUnavailable)
            } ?? false,
            attempt: attempt
        )
    }

    static func shouldAdvanceEndpoint(after error: Error?) -> Bool {
        if case .negotiationTimeout = error as? OpenVPNError {
            return true
        }

        guard let connectionError = error as? ConnectionError else {
            return false
        }

        switch connectionError.code {
            case .connectionRefused, .serverUnreachable, .connectionTimeout, .networkUnavailable, .handshakeTimeout:
                return true
            default:
                return false
        }
    }

    private func bringNetworkUp(remoteAddress: String, localOptions: OpenVPN.Configuration, remoteOptions: OpenVPN.Configuration, completionHandler: @escaping @Sendable (Error?) -> Void) {
        let newSettings = NetworkSettingsBuilder(
            remoteAddress: remoteAddress,
            localOptions: localOptions,
            remoteOptions: remoteOptions,
            fallbackDNSServers: fallbackDNSServers
        )

        guard !newSettings.isGateway || newSettings.hasGateway else {
            session?.shutdown(error: TunnelKitOpenVPNError.gatewayUnattainable)
            return
        }

//        // block LAN if desired
//        if routingPolicies?.contains(.blockLocal) ?? false {
//            let table = RoutingTable()
//            if isIPv4Gateway,
//                let gateway = table.defaultGateway4()?.gateway(),
//                let route = table.broadestRoute4(matchingDestination: gateway) {
//
//                route.partitioned()?.forEach {
//                    let destination = $0.network()
//                    guard let netmask = $0.networkMask() else {
//                        return
//                    }
//
//                    log.info("Block local: Suppressing IPv4 route \(destination)/\($0.prefix())")
//
//                    let included = NEIPv4Route(destinationAddress: destination, subnetMask: netmask)
//                    included.gatewayAddress = options.ipv4?.defaultGateway
//                    ipv4Settings?.includedRoutes?.append(included)
//                }
//            }
//            if isIPv6Gateway,
//                let gateway = table.defaultGateway6()?.gateway(),
//                let route = table.broadestRoute6(matchingDestination: gateway) {
//
//                route.partitioned()?.forEach {
//                    let destination = $0.network()
//                    let prefix = $0.prefix()
//
//                    log.info("Block local: Suppressing IPv6 route \(destination)/\($0.prefix())")
//
//                    let included = NEIPv6Route(destinationAddress: destination, networkPrefixLength: prefix as NSNumber)
//                    included.gatewayAddress = options.ipv6?.defaultGateway
//                    ipv6Settings?.includedRoutes?.append(included)
//                }
//            }
//        }

        setTunnelNetworkSettings(newSettings.build(), completionHandler: completionHandler)
    }
}

extension OpenVPNTunnelProvider {
    // MARK: Logging

    private func configureLogging() {
        loggingDestinations.forEach { log.removeDestination($0) }
        loggingDestinations.removeAll()

        let logLevel: SwiftyBeaver.Level = (cfg.shouldDebug ? debugLogLevel : .info)
        let logFormat = cfg.debugLogFormat ?? "$Dyyyy-MM-dd HH:mm:ss.SSS$d $L $N.$F:$l - $M"

        if cfg.shouldDebug {
            let console = ConsoleDestination()
            console.useNSLog = true
            console.minLevel = logLevel
            console.format = logFormat
            log.addDestination(console)
            loggingDestinations.append(console)
        }

        let file = FileDestination(logFileURL: cfg._appexDebugLogURL)
        file.minLevel = logLevel
        file.format = logFormat
        file.logFileMaxSize = maxLogSize
        log.addDestination(file)
        loggingDestinations.append(file)

        // store path for clients
        cfg._appexSetDebugLogPath()
    }

    private func flushLog() {
        log.debug("Flushing log...")

        // XXX: should enforce SwiftyBeaver flush?
//        if let url = cfg.urlForDebugLog {
//            memoryLog.flush(to: url)
//        }
    }

    private func logCurrentSSID() {
        InterfaceObserver.fetchCurrentSSID {
            if let ssid = $0 {
                log.debug("Current SSID: '\(ssid.maskedDescription)'")
            } else {
                log.debug("Current SSID: none (disconnected from WiFi)")
            }
        }
    }

//    private func anyPointer(_ object: Any?) -> UnsafeMutableRawPointer {
//        let anyObject = object as AnyObject
//        return Unmanaged<AnyObject>.passUnretained(anyObject).toOpaque()
//    }
}

// MARK: Errors

private extension OpenVPNTunnelProvider {
    enum ConfigurationError: Error {

        /// A field in the `OpenVPNProvider.Configuration` provided is incorrect or incomplete.
        case parameter(name: String)
    }

    func encryptedDNSValidationError() -> ConnectionError? {
        let dnsProtocol = cfg.configuration.dnsProtocol ?? .fallback
        let options = cfg.connectionValidation ?? .disabled
        return EncryptedDNSValidation.error(dnsProtocol: dnsProtocol, options: options)
    }
}

enum EncryptedDNSValidation {
    static func error(
        dnsProtocol: DNSProtocol,
        options: ConnectionValidationOptions
    ) -> ConnectionError? {
        guard dnsProtocol == .https || dnsProtocol == .tls, options.isEnabled else {
            return nil
        }

        var hasExplicitEndToEndProbe = false
        var hasImplicitDNSProbe = false
        for probe in options.probes {
            switch probe {
            case .ping:
                hasExplicitEndToEndProbe = true

            case .dns(hostname: _, server: .some):
                hasExplicitEndToEndProbe = true

            case .dns(hostname: _, server: .none):
                hasImplicitDNSProbe = true

            case .gatewayPing:
                break
            }
        }

        guard !hasExplicitEndToEndProbe || hasImplicitDNSProbe else {
            return nil
        }
        return ConnectionError(
            .unsupportedConfiguration,
            stage: .preparing,
            message: "DoH/DoT validation requires a numeric ping target or a DNS probe with an explicit plaintext server.",
            diagnostics: ["invalidFields": "connectionValidation.probes"]
        )
    }
}

private extension OpenVPNTunnelProvider {
    func setErrorStatus(with error: Error) {
        guard let cfg else {
            log.error("Unable to persist the tunnel error because provider configuration is unavailable")
            return
        }
        let legacyError = unifiedError(from: error)
        let connectionError = (error as? ConnectionError) ?? detailedError(for: legacyError, underlying: error)
        cfg._appexSetLastError(legacyError, connectionError: connectionError)
    }

    func unifiedError(from error: Error) -> TunnelKitOpenVPNError {
        if let legacyError = error as? TunnelKitOpenVPNError {
            return legacyError
        }
        if let connectionError = error as? ConnectionError {
            if let legacyCode = connectionError.diagnostics["legacyCode"],
               let legacyError = TunnelKitOpenVPNError(rawValue: legacyCode) {
                return legacyError
            }
            return connectionError.asTunnelKitOpenVPNError
        }
        return openVPNError(from: error) ?? .linkError
    }

    func detailedError(for legacyError: TunnelKitOpenVPNError, underlying: Error? = nil) -> ConnectionError {
        let code: ConnectionError.Code
        let stage: ConnectionStage
        switch legacyError {
        case .dnsFailure:
            (code, stage) = (.dnsFailure, .dnsResolution)

        case .exhaustedEndpoints, .serverUnreachable:
            (code, stage) = (.serverUnreachable, .socketConnection)

        case .socketActivity:
            (code, stage) = (.connectionTimeout, .socketConnection)

        case .authentication:
            (code, stage) = (.authenticationFailed, .authentication)

        case .tlsInitialization, .tlsServerVerification, .tlsHandshake,
                .encryptionInitialization, .lzo, .serverCompression, .unexpectedReply:
            (code, stage) = (.unsupportedConfiguration, .protocolHandshake)

        case .encryptionData, .linkError, .networkChanged, .serverShutdown:
            (code, stage) = (.connectionLost, .monitoring)

        case .timeout, .handshakeTimeout:
            (code, stage) = (.handshakeTimeout, .protocolHandshake)

        case .routing, .gatewayUnattainable:
            (code, stage) = (.routeConfigurationFailed, .applyingNetworkSettings)

        case .connectionValidationFailed:
            (code, stage) = (.validationFailed, .validation)

        case .cancelled:
            (code, stage) = (.cancelled, .disconnection)

        case .internalError:
            (code, stage) = (.internalError, .monitoring)
        }
        return ConnectionError(
            code,
            stage: stage,
            underlying: underlying,
            diagnostics: ["legacyCode": legacyError.rawValue]
        )
    }

    func normalizedConnectionError(_ error: Error?) -> ConnectionError? {
        guard let error else {
            return nil
        }
        if let connectionError = error as? ConnectionError {
            return connectionError
        }
        let legacyError = unifiedError(from: error)
        return detailedError(for: legacyError, underlying: error)
    }

    func openVPNError(from error: Error) -> TunnelKitOpenVPNError? {
        if let specificError = error.asNativeOpenVPNError ?? error as? OpenVPNError {
            switch specificError {
            case .negotiationTimeout, .pingTimeout, .staleSession:
                return .timeout

            case .badCredentials:
                return .authentication

            case .serverCompression:
                return .serverCompression

            case .failedLinkWrite, .failedLinkRead:
                return .linkError

            case .noRouting:
                return .routing

            case .serverShutdown:
                return .serverShutdown

            case .native(let code):
                switch code {
                case .cryptoRandomGenerator, .cryptoAlgorithm:
                    return .encryptionInitialization

                case .cryptoEncryption, .cryptoHMAC:
                    return .encryptionData

                case .tlscaRead, .tlscaUse, .tlscaPeerVerification,
                        .tlsClientCertificateRead, .tlsClientCertificateUse,
                        .tlsClientKeyRead, .tlsClientKeyUse:
                    return .tlsInitialization

                case .tlsServerCertificate, .tlsServerEKU, .tlsServerHost:
                    return .tlsServerVerification

                case .tlsHandshake:
                    return .tlsHandshake

                case .dataPathOverflow, .dataPathPeerIdMismatch:
                    return .unexpectedReply

                case .dataPathCompression:
                    return .serverCompression

                default:
                    break
                }

            default:
                return .unexpectedReply
            }
        }
        return nil
    }
}

/// Carries a weak provider reference across a `Task` boundary; all accesses
/// are funneled back onto the tunnel queue.
private final class WeakProviderBox: @unchecked Sendable {
    private(set) weak var provider: OpenVPNTunnelProvider?

    init(_ provider: OpenVPNTunnelProvider) {
        self.provider = provider
    }
}

private extension ConnectionError {

    /// Best-effort mapping to the serializable legacy error enum used for
    /// app-extension IPC. The full `ConnectionError` still reaches the OS
    /// through the start completion handler.
    var asTunnelKitOpenVPNError: TunnelKitOpenVPNError {
        switch code {
        case .dnsFailure:
            return .dnsFailure

        case .connectionTimeout:
            return .timeout

        case .handshakeTimeout:
            return .handshakeTimeout

        case .authenticationFailed:
            return .authentication

        case .serverUnreachable, .connectionRefused, .protocolBlocked:
            return .serverUnreachable

        case .tunnelSetupFailed, .routeConfigurationFailed:
            return .routing

        case .validationFailed:
            return .connectionValidationFailed

        case .networkUnavailable, .connectionLost:
            return .linkError

        case .cancelled:
            return .cancelled

        case .invalidConfiguration, .permissionDenied, .unsupportedConfiguration:
            return .unexpectedReply

        case .internalError:
            return .internalError
        }
    }
}

// MARK: Hacks

private extension OpenVPNTunnelProvider {
    func forceExitOnMac() {
        #if os(macOS)
        // Let queued NetworkExtension completions and error delivery leave the
        // lifecycle queue before applying the upstream macOS exit workaround.
        completionQueue.asyncAfter(deadline: .now() + .milliseconds(100)) {
            exit(0)
        }
        #endif
    }
}
