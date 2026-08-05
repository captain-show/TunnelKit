//
//  NWConnectionLink.swift
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
import TunnelKitAppExtension
import TunnelKitOpenVPNCore
import TunnelKitOpenVPNProtocol
import CTunnelKitOpenVPNProtocol

private let log = SwiftyBeaver.self

private final class UncheckedSendableCallback<Callback>: @unchecked Sendable {
    let callback: Callback

    init(_ callback: Callback) {
        self.callback = callback
    }
}

/// Signals that the stream peer closed the connection (TCP EOF). Surfaced as an
/// error so the session tears down instead of stalling until a ping timeout.
enum NWLinkError: Error {
    case remoteClosed
}

/// Tells apart the `NWError`s that cost one packet from the ones that cost the
/// link.
///
/// Under sustained throughput `NWConnection` reports per-operation POSIX
/// failures — `ENOBUFS` when the socket buffer is full, `EAGAIN`, `ENOMEM`,
/// `EINTR` — while staying `.ready` and perfectly usable. Reporting those as
/// link failures made the OpenVPN session reconnect (or shut down) the moment
/// traffic picked up, so a plain file download reproducibly dropped the tunnel.
enum NWLinkErrorPolicy {

    /// POSIX failures that cost a single datagram and leave the link usable.
    private static let recoverableCodes: Set<POSIXErrorCode> = [
        .ENOBUFS,   // socket buffer full: the classic high-throughput failure
        .ENOMEM,    // transient memory pressure in the networking stack
        .EAGAIN,    // == EWOULDBLOCK, the operation would have blocked
        .EINTR,     // interrupted syscall
        .EMSGSIZE,  // oversized datagram: only this packet is undeliverable
        .ENOSPC     // reported in place of ENOBUFS by some paths
    ]

    static func classify(_ error: NWError, operation: String) -> Error {
        guard case .posix(let code) = error,
              recoverableCodes.contains(code) else {
            return error
        }
        return TransientLinkError(operation: operation, underlying: error)
    }

    static func isRecoverable(_ error: NWError) -> Bool {
        guard case .posix(let code) = error else {
            return false
        }
        return recoverableCodes.contains(code)
    }
}

/// Aggregates every completion in one UDP send batch. A failure from an early
/// datagram must not be lost merely because the final datagram succeeded.
private final class SendBatchCompletion: @unchecked Sendable {
    private let lock = NSLock()

    private var remaining: Int

    private var firstError: Error?

    init(count: Int) {
        remaining = count
    }

    func record(_ error: Error?) -> (isComplete: Bool, error: Error?) {
        lock.lock()
        defer { lock.unlock() }

        if let error, firstError == nil || (firstError?.isTransientLinkFailure == true && !error.isTransientLinkFailure) {
            firstError = error
        }
        remaining -= 1
        return (remaining == 0, firstError)
    }
}

/// UDP `LinkInterface` over an `NWConnection`.
///
/// Thread-safety / `@unchecked Sendable`: the wrapped `NWConnection` was
/// started on the read queue by `NWConnectionSocket`, so every receive/send
/// completion is delivered on that single serial queue. `setReadHandler` must
/// be called with that same queue (it always is, in `OpenVPNTunnelProvider`).
/// All mutable state — including the in-flight receive count and the pending
/// batch — is confined to that queue, which is also why several concurrent
/// receives cannot interleave: their completions are serialized there.
final class NWUDPLink: LinkInterface, @unchecked Sendable {

    /// Receives kept in flight at once.
    ///
    /// With a single outstanding `receiveMessage` the kernel can only hand over
    /// the next datagram after this process has finished decrypting the previous
    /// one and writing it to the tunnel. At download rates that means the socket
    /// buffer overflows, which shows up as heavy packet loss and `ENOBUFS`.
    /// Several concurrent receives let the buffer keep draining while a batch is
    /// being processed. `NWConnection` still delivers the completions in arrival
    /// order on the (serial) connection queue, so datagram ordering is intact.
    private static let maxOutstandingReceives = 8

    private static let maxBatchedDatagrams = 64

    private let connection: NWConnection

    private let maxDatagrams: Int

    private let xor: XORProcessor

    private let remoteHost: String?

    private let remotePort: UInt16

    private var readHandler: (([Data]?, Error?) -> Void)?

    private var outstandingReceives = 0

    private var pendingDatagrams: [Data] = []

    private var isFlushScheduled = false

    private var isReceiving = false

    private var queue: DispatchQueue?

    init(connection: NWConnection, maxDatagrams: Int = 200, xorMethod: OpenVPN.XORMethod?, remoteHost: String?, remotePort: UInt16) {
        self.connection = connection
        self.maxDatagrams = maxDatagrams
        xor = XORProcessor(method: xorMethod)
        self.remoteHost = remoteHost
        self.remotePort = remotePort
    }

    // MARK: LinkInterface

    let isReliable = false

    var remoteAddress: String? {
        remoteHost
    }

    var remoteProtocol: String? {
        "UDP:\(remotePort)"
    }

    var packetBufferSize: Int {
        maxDatagrams
    }

    func setReadHandler(queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
        readHandler = handler
        self.queue = queue
        isReceiving = true
        armReceives()
    }

    /// Tops the in-flight receives back up to `maxOutstandingReceives`.
    private func armReceives() {
        while isReceiving, outstandingReceives < Self.maxOutstandingReceives {
            outstandingReceives += 1
            receiveOneDatagram()
        }
    }

    private func receiveOneDatagram() {
        connection.receiveMessage { [weak self] data, _, isComplete, error in
            // delivered on the connection queue (== read queue)
            guard let self else {
                return
            }
            self.outstandingReceives -= 1
            guard self.isReceiving else {
                return
            }

            if let error {
                if let nwError = error as? NWError, NWLinkErrorPolicy.isRecoverable(nwError) {
                    log.debug("Recoverable datagram receive failure, continuing: \(error)")
                    self.armReceives()
                    return
                }
                self.stopReceiving()
                self.flushPendingDatagrams()
                self.readHandler?(nil, error)
                return
            }

            if let data, !data.isEmpty {
                self.pendingDatagrams.append(data)
            }

            // NOTE: for a UDP NWConnection, `isComplete` is true for EVERY
            // datagram (each datagram is one complete message), so it must NOT
            // be treated as end-of-connection the way TCP streams are. The
            // connection is only done when a completion arrives with no content
            // AND isComplete (delivered on cancel/close); stop the loop then to
            // avoid re-arming forever on a dead connection.
            if isComplete && data == nil {
                self.stopReceiving()
                self.flushPendingDatagrams()
                self.readHandler?(nil, NWLinkError.remoteClosed)
                return
            }

            if self.pendingDatagrams.count >= Self.maxBatchedDatagrams {
                self.flushPendingDatagrams()
            } else {
                self.scheduleFlush()
            }
            self.armReceives()
        }
    }

    /// Defers the flush by one queue turn so datagrams that already arrived are
    /// handed to the session as a single batch, which lets the data path decrypt
    /// them in one pass and write them to the tunnel in one call.
    private func scheduleFlush() {
        guard !isFlushScheduled, !pendingDatagrams.isEmpty, let queue else {
            return
        }
        isFlushScheduled = true
        queue.async { [weak self] in
            self?.flushPendingDatagrams()
        }
    }

    private func flushPendingDatagrams() {
        isFlushScheduled = false
        guard !pendingDatagrams.isEmpty else {
            return
        }
        let datagrams = pendingDatagrams
        pendingDatagrams.removeAll(keepingCapacity: true)
        readHandler?(xor.processPackets(datagrams, outbound: false), nil)
    }

    private func stopReceiving() {
        isReceiving = false
    }

    func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        let dataToUse = xor.processPacket(packet, outbound: true)
        let completion = completionHandler.map(UncheckedSendableCallback.init)
        connection.send(content: dataToUse, completion: .contentProcessed { error in
            completion?.callback(Self.sendFailure(error))
        })
    }

    func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let packetsToUse = xor.processPackets(packets, outbound: true)
        guard !packetsToUse.isEmpty else {
            completionHandler?(nil)
            return
        }
        let batchCompletion = SendBatchCompletion(count: packetsToUse.count)
        let completion = completionHandler.map(UncheckedSendableCallback.init)
        connection.batch {
            for packet in packetsToUse {
                connection.send(content: packet, completion: .contentProcessed { error in
                    let outcome = batchCompletion.record(Self.sendFailure(error))
                    if outcome.isComplete {
                        completion?.callback(outcome.error)
                    }
                })
            }
        }
    }

    private static func sendFailure(_ error: NWError?) -> Error? {
        error.map { NWLinkErrorPolicy.classify($0, operation: "write") }
    }
}

/// TCP `LinkInterface` over an `NWConnection`.
///
/// Same confinement/`@unchecked Sendable` rationale as `NWUDPLink`.
final class NWTCPLink: LinkInterface, @unchecked Sendable {
    private let connection: NWConnection

    private let maxPacketSize: Int

    private let xorMethod: OpenVPN.XORMethod?

    private let xorMask: Data?

    private let remoteHost: String?

    private let remotePort: UInt16

    private var readHandler: (([Data]?, Error?) -> Void)?

    private var buffer = Data()

    init(connection: NWConnection, maxPacketSize: Int = 512 * 1024, xorMethod: OpenVPN.XORMethod?, remoteHost: String?, remotePort: UInt16) {
        self.connection = connection
        self.maxPacketSize = maxPacketSize
        self.xorMethod = xorMethod
        xorMask = xorMethod?.mask
        self.remoteHost = remoteHost
        self.remotePort = remotePort
    }

    // MARK: LinkInterface

    let isReliable = true

    var remoteAddress: String? {
        remoteHost
    }

    var remoteProtocol: String? {
        "TCP:\(remotePort)"
    }

    var packetBufferSize: Int {
        maxPacketSize
    }

    func setReadHandler(queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
        readHandler = handler
        loopReadStream()
    }

    private func loopReadStream() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: maxPacketSize) { [weak self] data, _, isComplete, error in
            // delivered on the connection queue (== read queue)
            guard let self else {
                return
            }
            if let error {
                if let nwError = error as? NWError, NWLinkErrorPolicy.isRecoverable(nwError) {
                    log.debug("Recoverable stream receive failure, continuing: \(error)")
                    self.loopReadStream()
                    return
                }
                self.readHandler?(nil, error)
                return
            }
            if let data, !data.isEmpty {
                self.buffer.append(data)
                var until = 0
                let packets = PacketStream.packets(
                    fromInboundStream: self.buffer,
                    until: &until,
                    xorMethod: self.xorMethod?.native ?? .none,
                    xorMask: self.xorMask
                )
                self.buffer = self.buffer.subdata(in: until..<self.buffer.count)
                if !packets.isEmpty {
                    self.readHandler?(packets, nil)
                }
            }
            if isComplete {
                // remote closed the stream: surface EOF so the session shuts
                // down instead of hanging until a ping timeout
                self.readHandler?(nil, NWLinkError.remoteClosed)
                return
            }
            self.loopReadStream()
        }
    }

    func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        let stream = PacketStream.outboundStream(
            fromPacket: packet,
            xorMethod: xorMethod?.native ?? .none,
            xorMask: xorMask
        )
        let completion = completionHandler.map(UncheckedSendableCallback.init)
        connection.send(content: stream, completion: .contentProcessed { error in
            completion?.callback(Self.sendFailure(error))
        })
    }

    func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let stream = PacketStream.outboundStream(
            fromPackets: packets,
            xorMethod: xorMethod?.native ?? .none,
            xorMask: xorMask
        )
        let completion = completionHandler.map(UncheckedSendableCallback.init)
        connection.send(content: stream, completion: .contentProcessed { error in
            completion?.callback(Self.sendFailure(error))
        })
    }

    private static func sendFailure(_ error: NWError?) -> Error? {
        error.map { NWLinkErrorPolicy.classify($0, operation: "write") }
    }
}

// MARK: LinkProducer

extension NWConnectionSocket: LinkProducer {
    public func link(userObject: Any?) -> LinkInterface {
        let xorMethod = userObject as? OpenVPN.XORMethod
        if isReliable {
            return NWTCPLink(connection: connection, xorMethod: xorMethod, remoteHost: remoteAddress, remotePort: remotePort)
        }
        return NWUDPLink(connection: connection, xorMethod: xorMethod, remoteHost: remoteAddress, remotePort: remotePort)
    }
}
