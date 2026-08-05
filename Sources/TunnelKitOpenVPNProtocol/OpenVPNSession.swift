//
//  OpenVPNSession.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 2/3/17.
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

import Foundation
import os
import SwiftyBeaver
import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
// The C protocol layer (ControlPacket, DataPath, TLSBox, …) predates Sendable
// annotations. Its packet objects are produced and consumed only on the
// session queue, so importing it as pre-concurrency is safe.
@preconcurrency import CTunnelKitOpenVPNProtocol

private let log = SwiftyBeaver.self

private final class UncheckedSendableValue<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

/// Observes major events notified by a `OpenVPNSession`.
public protocol OpenVPNSessionDelegate: AnyObject {

    /**
     Called after starting a session.
     
     - Parameter remoteAddress: The address of the VPN server.
     - Parameter remoteProtocol: The protocol of the VPN server, if specified.
     - Parameter options: The pulled tunnel settings.
     */
    func sessionDidStart(_: OpenVPNSession, remoteAddress: String, remoteProtocol: String?, options: OpenVPN.Configuration)

    /**
     Called as soon as a session starts stopping, before exit notification and
     transport teardown complete.

     - Parameter error: The reason for stopping, when available.
     - Parameter shouldReconnect: Whether the session requested recovery.
     */
    func sessionWillStop(_: OpenVPNSession, withError error: Error?, shouldReconnect: Bool)

    /**
     Called after stopping a session.
     
     - Parameter error: An optional `Error` being the reason of the stop.
     - Parameter shouldReconnect: When `true`, the session can/should be restarted. Usually because the stop reason was recoverable.
     - Seealso: `OpenVPNSession.reconnect(...)`
     */
    func sessionDidStop(_: OpenVPNSession, withError error: Error?, shouldReconnect: Bool)
}

public extension OpenVPNSessionDelegate {
    func sessionWillStop(_: OpenVPNSession, withError _: Error?, shouldReconnect _: Bool) {
    }
}

/// Provides methods to set up and maintain an OpenVPN session.
///
/// `@unchecked Sendable`: the session is a single-serial-queue engine. Every
/// mutable member is read and written only on `queue` — the read loops, the
/// negotiation/ping timers, and all `link`/`tunnel` completion callbacks hop
/// back onto it (see the `queue.sync`/`queue.async` guards throughout). The
/// provider performs its one-time setup (`delegate`, `credentials`) before the
/// first `tunnelQueue.sync` barrier, which happens-before all queue work. This
/// confinement — not the type system — is what makes the class thread-safe, so
/// it cannot be an actor without an async rewrite of the hot packet path.
public final class OpenVPNSession: Session, @unchecked Sendable {
    private enum StopMethod {
        case shutdown

        case reconnect
    }

    // MARK: Configuration

    /// The session base configuration.
    public let configuration: OpenVPN.Configuration

    /// The optional credentials.
    public var credentials: OpenVPN.Credentials?

    private var keepAliveInterval: TimeInterval? {
        let interval: TimeInterval?
        if let negInterval = pushReply?.options.keepAliveInterval, negInterval > 0.0 {
            interval = negInterval
        } else if let cfgInterval = configuration.keepAliveInterval, cfgInterval > 0.0 {
            interval = cfgInterval
        } else {
            return nil
        }
        return interval
    }

    private var keepAliveTimeout: TimeInterval {
        if let negTimeout = pushReply?.options.keepAliveTimeout, negTimeout > 0.0 {
            return negTimeout
        } else if let cfgTimeout = configuration.keepAliveTimeout, cfgTimeout > 0.0 {
            return cfgTimeout
        } else {
            return CoreConfiguration.OpenVPN.pingTimeout
        }
    }

    /// An optional `OpenVPNSessionDelegate` for receiving session events.
    public weak var delegate: OpenVPNSessionDelegate?

    // MARK: State

    private let queue: DispatchQueue

    private var tlsObserver: NSObjectProtocol?

    private var withLocalOptions: Bool

    private var keys: [UInt8: OpenVPN.SessionKey]

    private var oldKeys: [OpenVPN.SessionKey]

    private var negotiationKeyIdx: UInt8

    private var currentKeyIdx: UInt8?

    private var isRenegotiating: Bool

    private var negotiationKey: OpenVPN.SessionKey? {
        keys[negotiationKeyIdx]
    }

    private var currentKey: OpenVPN.SessionKey? {
        guard let i = currentKeyIdx else {
            return nil
        }
        return keys[i]
    }

    private var link: LinkInterface?

    private var tunnel: TunnelInterface?

    /// Observes decrypted inbound tunnel packets (used by connection validation).
    private struct InboundObserverState {
        var token = 0

        var observer: (@Sendable ([Data]) -> Void)?
    }

    private let inboundPacketObserver = OSAllocatedUnfairLock(initialState: InboundObserverState())

    private var isReliableLink: Bool {
        return link?.isReliable ?? false
    }

    private var continuatedPushReplyMessage: String?

    private var pushReply: OpenVPN.PushReply?

    private var nextPushRequestDate: Date?

    private var connectedDate: Date?

    private var lastPing: BidirectionalState<Date>

    /// Invalidates previously scheduled keep-alive blocks. Queue-confined.
    private var pingTimerGeneration: UInt64 = 0

    /// Fences delayed negotiation ticks from an earlier hard/soft reset.
    private var negotiationLoopGeneration: UInt64 = 0

    /// `true` after a stop has started and before cleanup completes.
    public private(set) var isStopping: Bool

    /// Recoverable link failures absorbed instead of stopping the session.
    /// Queue-confined; reported by the keep-alive tick for diagnostics.
    private var transientLinkReadFailures: UInt64 = 0

    private var transientLinkWriteFailures: UInt64 = 0

    /// Last reported values, so the tick only logs when something changed.
    private var lastReportedDropStatistics = DropStatistics()

    /// Keeps the compression-mismatch diagnosis to one line per session.
    private var hasReportedCompressionMismatch = false

    private struct DropStatistics: Equatable {
        var transientReads: UInt64 = 0

        var transientWrites: UInt64 = 0

        var undecryptable: UInt64 = 0

        var compression: UInt64 = 0

        var replayed: UInt64 = 0
    }

    /// Guards the single `deferStop` completion against double invocation.
    /// Queue-confined (only touched inside `deferStop` on `queue`).
    private var isStopCompleted = false

    /// The optional reason why the session stopped.
    public private(set) var stopError: Error?

    // MARK: Control

    private var controlChannel: OpenVPN.ControlChannel

    private var authenticator: OpenVPN.Authenticator?

    // MARK: Caching

    /// Each session owns its CA file. Reusing a process-wide filename lets a
    /// delayed deinit from an obsolete session delete the active session's CA.
    private let caURL: URL

    // MARK: Init

    /**
     Creates a VPN session.
     
     - Parameter queue: The `DispatchQueue` where to run the session loop.
     - Parameter configuration: The `Configuration` to use for this session.
     */
    public init(queue: DispatchQueue, configuration: OpenVPN.Configuration, cachesURL: URL) throws {
        guard let ca = configuration.ca else {
            throw OpenVPN.ConfigurationError.missingConfiguration(option: "ca")
        }

        self.queue = queue
        self.configuration = configuration
        self.caURL = cachesURL.appendingPathComponent("ca-\(UUID().uuidString).pem")

        withLocalOptions = true
        keys = [:]
        oldKeys = []
        negotiationKeyIdx = 0
        isRenegotiating = false
        lastPing = BidirectionalState(withResetValue: Date.distantPast)
        isStopping = false

        if let tlsWrap = configuration.tlsWrap {
            switch tlsWrap.strategy {
            case .auth:
                controlChannel = try OpenVPN.ControlChannel(withAuthKey: tlsWrap.key, digest: configuration.fallbackDigest)

            case .crypt:
                // a directionless key would trap later in cipherEncryptKey/cipherDecryptKey
                guard tlsWrap.key.direction != nil else {
                    throw OpenVPN.ConfigurationError.malformed(option: "tls-crypt key requires a direction")
                }
                controlChannel = try OpenVPN.ControlChannel(withCryptKey: tlsWrap.key)
            }
        } else {
            controlChannel = OpenVPN.ControlChannel()
        }

        // cache CA locally (mandatory for OpenSSL)
        try ca.pem.write(to: caURL, atomically: true, encoding: .ascii)
    }

    deinit {
        cleanup()
        cleanupCache()
    }

    // MARK: Session

    public func setLink(_ link: LinkInterface) {
        guard self.link == nil else {
            log.warning("Link interface already set!")
            return
        }

        log.debug("Starting VPN session")

        // WARNING: runs in notification source queue (we know it's "queue", but better be safe than sorry)
        tlsObserver = NotificationCenter.default.addObserver(forName: .TLSBoxPeerVerificationError, object: nil, queue: nil) { [weak self] (notification) in
            let error = notification.userInfo?[OpenVPNErrorKey] as? Error
            guard let self else {
                return
            }
            self.queue.async {
                self.deferStop(.shutdown, error)
            }
        }

        self.link = link
        start()
    }

    public func canRebindLink() -> Bool {
//        return (pushReply?.peerId != nil)

        // FIXME: floating is currently unreliable
        return false
    }

    public func rebindLink(_ link: LinkInterface) {
        guard let _ = pushReply?.options.peerId else {
            log.warning("Session doesn't support link rebinding!")
            return
        }

        isStopping = false
        stopError = nil

        log.debug("Rebinding VPN session to a new link")
        self.link = link
        loopLink()
    }

    public func setTunnel(tunnel: TunnelInterface) {
        guard self.tunnel == nil else {
            log.warning("Tunnel interface already set!")
            return
        }
        self.tunnel = tunnel
        loopTunnel()
    }

    public func dataCount() -> DataCount? {
        guard let _ = link else {
            return nil
        }
        return controlChannel.currentDataCount()
    }

    public func serverConfiguration() -> Any? {
        return pushReply?.options
    }

    public func shutdown(error: Error?) {
        guard !isStopping else {
            log.warning("Ignore stop request, already stopping!")
            return
        }
        deferStop(.shutdown, error)
    }

    public func reconnect(error: Error?) {
        guard !isStopping else {
            log.warning("Ignore stop request, already stopping!")
            return
        }
        deferStop(.reconnect, error)
    }

    // Ruby: cleanup
    public func cleanup() {
        log.info("Cleaning up...")

        if let observer = tlsObserver {
            NotificationCenter.default.removeObserver(observer)
            tlsObserver = nil
        }

        keys.removeAll()
        oldKeys.removeAll()
        negotiationKeyIdx = 0
        currentKeyIdx = nil
        isRenegotiating = false

        nextPushRequestDate = nil
        connectedDate = nil
        authenticator = nil
        continuatedPushReplyMessage = nil
        pushReply = nil
        link = nil
        if !(tunnel?.isPersistent ?? false) {
            tunnel = nil
        }

        isStopping = false
        stopError = nil
        pingTimerGeneration &+= 1
        negotiationLoopGeneration &+= 1
        inboundPacketObserver.withLock { $0.observer = nil }
        transientLinkReadFailures = 0
        transientLinkWriteFailures = 0
        lastReportedDropStatistics = DropStatistics()
        hasReportedCompressionMismatch = false
    }

    func cleanupCache() {
        let fm = FileManager.default
        for url in [caURL] {
            try? fm.removeItem(at: url)
        }
    }

    // MARK: Loop

    // Ruby: start
    private func start() {
        loopLink()
        hardReset()
    }

    private func loopNegotiation(generation: UInt64) {
        guard generation == negotiationLoopGeneration, !isStopping else {
            return
        }
        guard let link = link else {
            return
        }
        guard let negotiationKey else {
            deferStop(.shutdown, internalInvariantError("The negotiation key is missing."))
            return
        }

        // go through deferStop so isStopping is honored and the delegate
        // cannot be notified twice
        guard !negotiationKey.didHardResetTimeOut(link: link) else {
            deferStop(.reconnect, OpenVPNError.negotiationTimeout)
            return
        }
        guard !negotiationKey.didNegotiationTimeOut(link: link) else {
            deferStop(.shutdown, OpenVPNError.negotiationTimeout)
            return
        }

        pushRequest()
        if !isReliableLink {
            flushControlQueue()
        }

        guard negotiationKey.controlState == .connected else {
            queue.asyncAfter(deadline: .now() + CoreConfiguration.OpenVPN.tickInterval) { [weak self] in
                guard let self, generation == self.negotiationLoopGeneration else {
                    return
                }
                self.loopNegotiation(generation: generation)
            }
            return
        }

        // let loop die when negotiation is complete
    }

    // Ruby: udp_loop
    private func loopLink() {
        guard let loopedLink = link else {
            return
        }
        loopedLink.setReadHandler(queue: queue) { [weak self, weak loopedLink] (newPackets, error) in
            guard let self, let loopedLink else {
                return
            }
            guard self.link === loopedLink else {
                log.warning("Ignoring read from outdated LINK")
                return
            }
            if let error = error {
                guard !error.isTransientLinkFailure else {
                    self.transientLinkReadFailures += 1
                    log.debug("Recoverable LINK read failure, dropping packet: \(error)")
                    return
                }
                log.error("Failed LINK read: \(error)")

                // a dead link must not leave the session hanging until the
                // ping timeout; trigger a reconnection through the socket
                self.deferStop(.reconnect, self.linkFailure(operation: "read", underlying: error))
                return
            }

            if let packets = newPackets, !packets.isEmpty {
                self.maybeRenegotiate()

                self.receiveLink(packets: packets)
            }
        }
    }

    // Ruby: tun_loop
    private func loopTunnel() {
        guard let loopedTunnel = tunnel else {
            return
        }

        loopedTunnel.setReadHandler(queue: queue) { [weak self, weak loopedTunnel] (newPackets, error) in
            guard let self, let loopedTunnel, self.tunnel === loopedTunnel else {
                log.warning("Ignoring read from outdated TUN")
                return
            }

            if let error = error {
                log.error("Failed TUN read: \(error)")
                return
            }

            if let packets = newPackets, !packets.isEmpty {
                self.receiveTunnel(packets: packets)
            }
        }
    }

    // Ruby: recv_link
    private func receiveLink(packets: [Data]) {
        guard shouldHandlePackets() else {
            log.warning("Discarding \(packets.count) LINK packets (should not handle)")
            return
        }

        lastPing.inbound = Date()

        var dataPacketsByKey = [UInt8: [Data]]()

        for packet in packets {
            guard !isStopping else {
                return
            }

            guard let firstByte = packet.first else {
                log.warning("Dropped malformed packet (missing opcode)")
                continue
            }
            let codeValue = firstByte >> 3
            guard let code = PacketCode(rawValue: codeValue) else {
                log.warning("Dropped malformed packet (unknown code: \(codeValue))")
                continue
            }

            var offset = 1
            if code == .dataV2 {
                guard packet.count >= offset + PacketPeerIdLength else {
                    log.warning("Dropped malformed packet (missing peerId)")
                    continue
                }
                offset += PacketPeerIdLength
            }

            if (code == .dataV1) || (code == .dataV2) {
                let key = firstByte & 0b111
                guard let _ = keys[key] else {
                    log.warning("Key with id \(key) not found")
//                    deferStop(.shutdown, OpenVPNError.badKey)
                    continue // JK: This used to be return, but we'd see connections that would stay in Connecting… state forever
                }

                // append in place to avoid a per-packet copy-on-write of the
                // grouped array in this hot receive path
                dataPacketsByKey[key, default: [Data]()].append(packet)

                continue
            }

            let controlPacket: ControlPacket
            do {
                let parsedPacket = try controlChannel.readInboundPacket(withData: packet, offset: 0)
                handleAcks()
                if parsedPacket.code == .ackV1 {
                    continue
                }
                controlPacket = parsedPacket
            } catch {
                log.warning("Dropped malformed packet: \(error)")
                continue
//                deferStop(.shutdown, e)
//                return
            }
            switch code {
            case .hardResetServerV2:

                // HARD_RESET coming during a SOFT_RESET handshake (before connecting)
                guard !isRenegotiating else {
                    deferStop(.shutdown, OpenVPNError.staleSession)
                    return
                }

            case .softResetV1:
                if !isRenegotiating {
                    softReset(isServerInitiated: true)
                }

            default:
                break
            }

            sendAck(for: controlPacket)

            let pendingInboundQueue = controlChannel.enqueueInboundPacket(packet: controlPacket)
            for inboundPacket in pendingInboundQueue {
                handleControlPacket(inboundPacket)
                guard !isStopping else {
                    return
                }
            }
        }

        // send decrypted packets to tunnel all at once
        guard !isStopping else {
            return
        }
        for (keyId, dataPackets) in dataPacketsByKey {
            guard !isStopping else {
                return
            }
            guard let sessionKey = keys[keyId] else {
                log.warning("Accounted a data packet for which the cryptographic key hadn't been found")
                continue
            }
            handleDataPackets(dataPackets, key: sessionKey)
        }
    }

    // Ruby: recv_tun
    private func receiveTunnel(packets: [Data]) {
        guard shouldHandlePackets() else {
            log.warning("Discarding \(packets.count) TUN packets (should not handle)")
            return
        }
        sendDataPackets(packets)
    }

    // Ruby: ping
    private func ping() {
        guard currentKey?.controlState == .connected else {
            return
        }

        let now = Date()
        guard now.timeIntervalSince(lastPing.inbound) <= keepAliveTimeout else {
            deferStop(.reconnect, ConnectionError(
                .connectionLost,
                stage: .monitoring,
                message: "The OpenVPN peer stopped responding to keep-alive traffic.",
                diagnostics: ["operation": "keep-alive"]
            ))
            return
        }

        reportDropStatistics()

        // is keep-alive enabled?
        if let _ = keepAliveInterval {
            log.debug("Send ping")
            sendDataPackets([OpenVPN.DataPacket.pingString])
            lastPing.outbound = Date()
        }

        // schedule even just to check for ping timeout
        scheduleNextPing()
    }

    /**
     Surfaces packets the data path dropped instead of stopping the session.

     Dropping is the correct behavior, but silence would hide a real
     misconfiguration (a server compressing traffic this client cannot decode,
     a peer-id mismatch, a link that constantly overflows), so the counters are
     logged whenever they move.
     */
    private func reportDropStatistics() {
        let dataPath = currentKey?.dataPath
        let current = DropStatistics(
            transientReads: transientLinkReadFailures,
            transientWrites: transientLinkWriteFailures,
            undecryptable: dataPath?.droppedInboundPackets ?? 0,
            compression: dataPath?.droppedCompressedInboundPackets ?? 0,
            replayed: dataPath?.droppedReplayedInboundPackets ?? 0
        )
        guard current != lastReportedDropStatistics else {
            return
        }
        lastReportedDropStatistics = current
        log.info("""
            Dropped packets so far: \(current.undecryptable) undecryptable \
            (\(current.compression) compression), \(current.replayed) replayed, \
            \(current.transientReads) recoverable reads, \
            \(current.transientWrites) recoverable writes
            """)

        if current.compression > 0, !hasReportedCompressionMismatch {
            hasReportedCompressionMismatch = true
            log.error("""
                The server is sending compressed data packets that this client \
                cannot decompress (framing: \
                \(pushReply?.options.compressionFraming ?? configuration.fallbackCompressionFraming), \
                algorithm: \(pushReply?.options.compressionAlgorithm ?? configuration.compressionAlgorithm ?? .disabled)). \
                Such packets are dropped, which degrades throughput: disable \
                compression server-side (comp-lzo no / compress stub) or build \
                with an LZO provider.
                """)
        }
    }

    private func scheduleNextPing() {
        let interval: TimeInterval
        if let keepAliveInterval = keepAliveInterval {
            interval = keepAliveInterval
            log.verbose("Schedule ping after \(interval.asTimeString)")
        } else {
            interval = CoreConfiguration.OpenVPN.pingTimeoutCheckInterval
            log.verbose("Schedule ping timeout check after \(interval.asTimeString)")
        }
        pingTimerGeneration &+= 1
        let generation = pingTimerGeneration
        queue.asyncAfter(deadline: .now() + interval) { [weak self] in
            guard let self,
                  self.pingTimerGeneration == generation,
                  !self.isStopping else {
                return
            }
            log.verbose("Running ping block")
            self.ping()
        }
    }

    // MARK: Handshake

    // Ruby: reset_ctrl
    @discardableResult
    private func resetControlChannel(forNewSession: Bool) -> Bool {
        authenticator = nil
        do {
            try controlChannel.reset(forNewSession: forNewSession)
            return true
        } catch {
            deferStop(.shutdown, error)
            return false
        }
    }

    // Ruby: hard_reset
    private func hardReset() {
        log.debug("Send hard reset")

        guard resetControlChannel(forNewSession: true) else {
            return
        }
        continuatedPushReplyMessage = nil
        pushReply = nil
        negotiationKeyIdx = 0
        let newKey = OpenVPN.SessionKey(id: UInt8(negotiationKeyIdx), timeout: CoreConfiguration.OpenVPN.negotiationTimeout)
        keys[negotiationKeyIdx] = newKey
        log.debug("Negotiation key index is \(negotiationKeyIdx)")

        let payload = hardResetPayload() ?? Data()
        newKey.state = .hardReset
        negotiationLoopGeneration &+= 1
        loopNegotiation(generation: negotiationLoopGeneration)
        enqueueControlPackets(code: .hardResetClientV2, key: UInt8(negotiationKeyIdx), payload: payload)
    }

    private func hardResetPayload() -> Data? {
        guard !(configuration.usesPIAPatches ?? false) else {
            guard let _ = configuration.ca else {
                log.error("Configuration doesn't have a CA")
                return nil
            }
            let caMD5: String
            do {
                caMD5 = try TLSBox.md5(forCertificatePath: caURL.path)
            } catch {
                log.error("CA MD5 could not be computed, skipping custom HARD_RESET")
                return nil
            }
            log.debug("CA MD5 is: \(caMD5)")
            return try? PIAHardReset(
                caMd5Digest: caMD5,
                cipher: configuration.fallbackCipher,
                digest: configuration.fallbackDigest
            ).encodedData()
        }
        return nil
    }

    // Ruby: soft_reset
    private func softReset(isServerInitiated: Bool) {
        guard !isRenegotiating else {
            log.warning("Renegotiation already in progress")
            return
        }
        if isServerInitiated {
            log.debug("Handle soft reset")
        } else {
            log.debug("Send soft reset")
        }

        guard resetControlChannel(forNewSession: false) else {
            return
        }
        negotiationKeyIdx = max(1, (negotiationKeyIdx + 1) % OpenVPN.ProtocolMacros.numberOfKeys)
        let newKey = OpenVPN.SessionKey(id: UInt8(negotiationKeyIdx), timeout: CoreConfiguration.OpenVPN.softNegotiationTimeout)
        keys[negotiationKeyIdx] = newKey
        log.debug("Negotiation key index is \(negotiationKeyIdx)")

        newKey.state = .softReset
        isRenegotiating = true
        negotiationLoopGeneration &+= 1
        loopNegotiation(generation: negotiationLoopGeneration)
        if !isServerInitiated {
            enqueueControlPackets(code: .softResetV1, key: UInt8(negotiationKeyIdx), payload: Data())
        }
    }

    // Ruby: on_tls_connect
    private func onTLSConnect() {
        log.debug("TLS.connect: Handshake is complete")

        guard let negotiationKey, let tls = negotiationKey.tlsOptional else {
            deferStop(.shutdown, internalInvariantError("TLS connected without a negotiation key or TLS context."))
            return
        }

        negotiationKey.controlState = .preAuth

        do {
            authenticator = try OpenVPN.Authenticator(credentials?.username, pushReply?.options.authToken ?? credentials?.password)
            authenticator?.withLocalOptions = withLocalOptions
            try authenticator?.putAuth(into: tls, options: configuration)
        } catch {
            deferStop(.shutdown, error)
            return
        }

        let cipherTextOut: Data
        do {
            cipherTextOut = try tls.pullCipherText()
        } catch {
            if let nativeError = error.asNativeOpenVPNError {
                log.error("TLS.auth: Failed pulling ciphertext (error: \(nativeError))")
                shutdown(error: nativeError)
                return
            }
            log.verbose("TLS.auth: Still can't pull ciphertext")
            return
        }

        log.debug("TLS.auth: Pulled ciphertext (\(cipherTextOut.count) bytes)")
        enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
    }

    // Ruby: push_request
    private func pushRequest() {
        guard let negotiationKey else {
            if !isStopping {
                deferStop(.shutdown, internalInvariantError("Cannot push configuration without a negotiation key."))
            }
            return
        }
        guard negotiationKey.controlState == .preIfConfig else {
            return
        }
        guard let tls = negotiationKey.tlsOptional else {
            if !isStopping {
                deferStop(.shutdown, internalInvariantError("Cannot push configuration without an active TLS context."))
            }
            return
        }
        guard let targetDate = nextPushRequestDate, Date() > targetDate else {
            return
        }

        log.debug("TLS.ifconfig: Put plaintext (PUSH_REQUEST)")
        try? tls.putPlainText("PUSH_REQUEST\0")

        let cipherTextOut: Data
        do {
            cipherTextOut = try tls.pullCipherText()
        } catch {
            if let nativeError = error.asNativeOpenVPNError {
                log.error("TLS.auth: Failed pulling ciphertext (error: \(nativeError))")
                shutdown(error: nativeError)
                return
            }
            log.verbose("TLS.ifconfig: Still can't pull ciphertext")
            return
        }

        log.debug("TLS.ifconfig: Send pulled ciphertext (\(cipherTextOut.count) bytes)")
        enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)

        if isRenegotiating {
            guard completeConnection() else {
                return
            }
            isRenegotiating = false
        }
        nextPushRequestDate = Date().addingTimeInterval(CoreConfiguration.OpenVPN.pushRequestInterval)
    }

    private func maybeRenegotiate() {
        guard let renegotiatesAfter = configuration.renegotiatesAfter, renegotiatesAfter > 0 else {
            return
        }
        guard negotiationKeyIdx == currentKeyIdx else {
            return
        }

        guard let negotiationKey else {
            deferStop(.shutdown, internalInvariantError("Cannot renegotiate without a negotiation key."))
            return
        }
        let elapsed = -negotiationKey.startTime.timeIntervalSinceNow
        if elapsed > renegotiatesAfter {
            log.debug("Renegotiating after \(elapsed.asTimeString)")
            softReset(isServerInitiated: false)
        }
    }

    @discardableResult
    private func completeConnection() -> Bool {
        guard !isStopping else {
            return false
        }
        guard let negotiationKey else {
            deferStop(.shutdown, internalInvariantError("Cannot complete a connection without a negotiation key."))
            return false
        }
        guard setupEncryption() else {
            return false
        }
        authenticator?.reset()
        negotiationKey.controlState = .connected
        connectedDate = Date()
        transitionKeys()
        return true
    }

    // MARK: Control

    // Ruby: handle_ctrl_pkt
    private func handleControlPacket(_ packet: ControlPacket) {
        guard let negotiationKey else {
            deferStop(.shutdown, internalInvariantError("Received a control packet without a negotiation key."))
            return
        }
        guard packet.key == negotiationKey.id else {
            log.error("Bad key in control packet (\(packet.key) != \(negotiationKey.id))")
//            deferStop(.shutdown, OpenVPNError.badKey)
            return
        }

        guard let _ = configuration.ca else {
            log.error("Configuration doesn't have a CA")
            return
        }

        // start new TLS handshake
        if ((packet.code == .hardResetServerV2) && (negotiationKey.state == .hardReset)) ||
            ((packet.code == .softResetV1) && (negotiationKey.state == .softReset)) {

            if negotiationKey.state == .hardReset {
                controlChannel.remoteSessionId = packet.sessionId
            }
            guard let remoteSessionId = controlChannel.remoteSessionId else {
                log.error("No remote sessionId (never set)")
                deferStop(.shutdown, OpenVPNError.missingSessionId)
                return
            }
            guard packet.sessionId == remoteSessionId else {
                log.error("Packet session mismatch (\(packet.sessionId.toHex()) != \(remoteSessionId.toHex()))")
                deferStop(.shutdown, OpenVPNError.sessionMismatch)
                return
            }

            negotiationKey.state = .tls

            log.debug("Start TLS handshake")

            let tls = TLSBox(
                caPath: caURL.path,
                clientCertificate: configuration.clientCertificate?.pem,
                clientKey: configuration.clientKey?.pem,
                checksEKU: configuration.checksEKU ?? false,
                checksSANHost: configuration.checksSANHost ?? false,
                hostname: configuration.sanHost
            )
            if let tlsSecurityLevel = configuration.tlsSecurityLevel {
                tls.securityLevel = tlsSecurityLevel
            }
            negotiationKey.tlsOptional = tls
            do {
                try tls.start()
            } catch {
                deferStop(.shutdown, error)
                return
            }

            let cipherTextOut: Data
            do {
                cipherTextOut = try tls.pullCipherText()
            } catch {
                if let nativeError = error.asNativeOpenVPNError {
                    log.error("TLS.connect: Failed pulling ciphertext (error: \(nativeError))")
                    shutdown(error: nativeError)
                    return
                }
                deferStop(.shutdown, error)
                return
            }

            log.debug("TLS.connect: Pulled ciphertext (\(cipherTextOut.count) bytes)")
            enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
        }
        // exchange TLS ciphertext
        else if (packet.code == .controlV1) && (negotiationKey.state == .tls) {
            guard let tls = negotiationKey.tlsOptional else {
                deferStop(.shutdown, internalInvariantError("Received TLS control data without a TLS context."))
                return
            }
            guard let remoteSessionId = controlChannel.remoteSessionId else {
                log.error("No remote sessionId found in packet (control packets before server HARD_RESET)")
                deferStop(.shutdown, OpenVPNError.missingSessionId)
                return
            }
            guard packet.sessionId == remoteSessionId else {
                log.error("Packet session mismatch (\(packet.sessionId.toHex()) != \(remoteSessionId.toHex()))")
                deferStop(.shutdown, OpenVPNError.sessionMismatch)
                return
            }

            guard let cipherTextIn = packet.payload else {
                log.warning("TLS.connect: Control packet with empty payload?")
                return
            }

            log.debug("TLS.connect: Put received ciphertext (\(cipherTextIn.count) bytes)")
            try? tls.putCipherText(cipherTextIn)

            let cipherTextOut: Data
            do {
                cipherTextOut = try tls.pullCipherText()
                log.debug("TLS.connect: Send pulled ciphertext (\(cipherTextOut.count) bytes)")
                enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
            } catch {
                if let nativeError = error.asNativeOpenVPNError {
                    log.error("TLS.connect: Failed pulling ciphertext (error: \(nativeError))")
                    shutdown(error: nativeError)
                    return
                }
                log.verbose("TLS.connect: No available ciphertext to pull")
            }

            if negotiationKey.shouldOnTLSConnect() {
                onTLSConnect()
            }

            do {
                while true {
                    let controlData = try controlChannel.currentControlData(withTLS: tls)
                    handleControlData(controlData)
                    guard !isStopping else {
                        return
                    }
                }
            } catch _ {
            }
        }
    }

    // Ruby: handle_ctrl_data
    private func handleControlData(_ data: ZeroingData) {
        guard !isStopping, let auth = authenticator, let negotiationKey else {
            return
        }

        if CoreConfiguration.logsSensitiveData {
            log.debug("Pulled plain control data (\(data.count) bytes): \(data.toHex())")
        } else {
            log.debug("Pulled plain control data (\(data.count) bytes)")
        }

        auth.appendControlData(data)

        if negotiationKey.controlState == .preAuth {
            do {
                guard try auth.parseAuthReply() else {
                    return
                }
            } catch {
                deferStop(.shutdown, error)
                return
            }

            negotiationKey.controlState = .preIfConfig
            nextPushRequestDate = Date()
            pushRequest()
            nextPushRequestDate?.addTimeInterval(isRenegotiating ? CoreConfiguration.OpenVPN.pushRequestInterval : CoreConfiguration.OpenVPN.retransmissionLimit)
        }

        for message in auth.parseMessages() {
            if CoreConfiguration.logsSensitiveData {
                let sanitizedMessage = OpenVPN.PushReply.sanitizedForLogging(message)
                log.debug("Parsed control message (\(message.count) bytes): \"\(sanitizedMessage)\"")
            } else {
                log.debug("Parsed control message (\(message.count) bytes)")
            }
            handleControlMessage(message)
            guard !isStopping else {
                return
            }
        }
    }

    // Ruby: handle_ctrl_msg
    private func handleControlMessage(_ message: String) {
        if CoreConfiguration.logsSensitiveData {
            log.debug("Received control message: \"\(OpenVPN.PushReply.sanitizedForLogging(message))\"")
        }

        // disconnect on authentication failure
        guard !message.hasPrefix("AUTH_FAILED") else {

            // XXX: retry without client options
            if authenticator?.withLocalOptions ?? false {
                log.warning("Authentication failure, retrying without local options")
                withLocalOptions = false
                deferStop(.reconnect, OpenVPNError.badCredentials)
                return
            }

            deferStop(.shutdown, OpenVPNError.badCredentials)
            return
        }

        // disconnect on remote server restart (--explicit-exit-notify)
        guard !message.hasPrefix("RESTART") else {
            log.debug("Disconnecting due to server shutdown")
            deferStop(.shutdown, OpenVPNError.serverShutdown)
            return
        }

        // handle authentication from now on
        guard negotiationKey?.controlState == .preIfConfig else {
            return
        }

        let completeMessage: String
        if let continuated = continuatedPushReplyMessage {
            completeMessage = "\(continuated),\(message)"
        } else {
            completeMessage = message
        }
        let reply: OpenVPN.PushReply
        do {
            guard let optionalReply = try OpenVPN.PushReply(message: completeMessage) else {
                return
            }
            reply = optionalReply
            log.debug("Received PUSH_REPLY: \"\(reply)\"")

            if let framing = reply.options.compressionFraming, let compression = reply.options.compressionAlgorithm {
                switch compression {
                case .disabled:
                    break

                case .LZO:
                    if !LZOFactory.isSupported() {
                        log.error("Server has LZO compression enabled and this was not built into the library (framing=\(framing))")
                        throw OpenVPNError.serverCompression
                    }

                case .other:
                    log.error("Server has non-LZO compression enabled and this is currently unsupported (framing=\(framing))")
                    throw OpenVPNError.serverCompression
                }
            }
        } catch OpenVPN.ConfigurationError.continuationPushReply {
            continuatedPushReplyMessage = completeMessage.replacingOccurrences(of: "push-continuation", with: "")
            // FIXME: strip "PUSH_REPLY" and "push-continuation 2"
            return
        } catch {
            deferStop(.shutdown, error)
            return
        }

        pushReply = reply
        guard reply.options.ipv4 != nil || reply.options.ipv6 != nil else {
            deferStop(.shutdown, OpenVPNError.noRouting)
            return
        }

        // if encryption setup failed, a shutdown is already in flight — do not
        // notify the delegate that the session started
        guard completeConnection() else {
            return
        }

        guard !isStopping else {
            return
        }
        guard let remoteAddress = link?.remoteAddress else {
            deferStop(.shutdown, internalInvariantError("Could not resolve link remote address"))
            return
        }
        guard !isStopping else {
            return
        }
        delegate?.sessionDidStart(
            self,
            remoteAddress: remoteAddress,
            remoteProtocol: link?.remoteProtocol,
            options: reply.options
        )

        scheduleNextPing()
    }

    // Ruby: transition_keys
    private func transitionKeys() {
        if let key = currentKey {
            oldKeys.append(key)
        }
        currentKeyIdx = negotiationKeyIdx
        cleanKeys()
    }

    // Ruby: clean_keys
    private func cleanKeys() {
        while oldKeys.count > 1 {
            let key = oldKeys.removeFirst()
            keys.removeValue(forKey: key.id)
        }
    }

    // Ruby: q_ctrl
    private func enqueueControlPackets(code: PacketCode, key: UInt8, payload: Data) {
        guard let _ = link else {
            log.warning("Not writing to LINK, interface is down")
            return
        }

        do {
            try controlChannel.enqueueOutboundPackets(withCode: code, key: key, payload: payload, maxPacketSize: 1000)
        } catch {
            log.error("Failed to enqueue control packets: \(error)")
            deferStop(.shutdown, error)
            return
        }
        flushControlQueue()
    }

    // Ruby: flush_ctrl_q_out
    private func flushControlQueue() {
        let rawList: [Data]
        do {
            rawList = try controlChannel.writeOutboundPackets()
        } catch {
            log.warning("Failed control packet serialization: \(error)")
            deferStop(.shutdown, error)
            return
        }
        for raw in rawList {
            log.debug("Send control packet (\(raw.count) bytes): \(raw.toHex())")
        }

        // WARNING: runs in Network.framework queue
        let writeLink = UncheckedSendableValue(link)
        link?.writePackets(rawList) { [weak self] (error) in
            guard let self else {
                return
            }
            self.queue.async {
                guard self.link === writeLink.value else {
                    log.warning("Ignoring write from outdated LINK")
                    return
                }
                if let error {
                    guard !error.isTransientLinkFailure else {
                        self.transientLinkWriteFailures += 1
                        log.debug("Recoverable LINK write failure during control flush, dropping: \(error)")
                        return
                    }
                    log.error("Failed LINK write during control flush: \(error)")
                    self.deferStop(.reconnect, self.linkFailure(operation: "control-write", underlying: error))
                    return
                }
            }
        }
    }

    // Ruby: setup_keys
    //
    // These guards protect invariants that a well-behaved server can never
    // violate, but a buggy or malicious server must not be able to crash the
    // tunnel process, so violations shut the session down instead of trapping.
    @discardableResult
    private func setupEncryption() -> Bool {
        guard let negotiationKey else {
            deferStop(.shutdown, internalInvariantError("Setting up encryption without a negotiation key"))
            return false
        }
        guard let auth = authenticator else {
            deferStop(.shutdown, internalInvariantError("Setting up encryption without having authenticated"))
            return false
        }
        guard let sessionId = controlChannel.sessionId else {
            deferStop(.shutdown, internalInvariantError("Setting up encryption without a local sessionId"))
            return false
        }
        guard let remoteSessionId = controlChannel.remoteSessionId else {
            deferStop(.shutdown, internalInvariantError("Setting up encryption without a remote sessionId"))
            return false
        }
        guard let serverRandom1 = auth.serverRandom1, let serverRandom2 = auth.serverRandom2 else {
            deferStop(.shutdown, internalInvariantError("Setting up encryption without server randoms"))
            return false
        }
        guard let pushReply = pushReply else {
            deferStop(.shutdown, internalInvariantError("Setting up encryption without a former PUSH_REPLY"))
            return false
        }

        if CoreConfiguration.logsSensitiveData {
            log.debug("Set up encryption from the following components:")
            log.debug("\tpreMaster: \(auth.preMaster.toHex())")
            log.debug("\trandom1: \(auth.random1.toHex())")
            log.debug("\trandom2: \(auth.random2.toHex())")
            log.debug("\tserverRandom1: \(serverRandom1.toHex())")
            log.debug("\tserverRandom2: \(serverRandom2.toHex())")
            log.debug("\tsessionId: \(sessionId.toHex())")
            log.debug("\tremoteSessionId: \(remoteSessionId.toHex())")
        } else {
            log.debug("Set up encryption")
        }

        let pushedCipher = pushReply.options.cipher
        if let negCipher = pushedCipher {
            log.info("\tNegotiated cipher: \(negCipher.rawValue)")
        }
        let pushedFraming = pushReply.options.compressionFraming
        if let negFraming = pushedFraming {
            log.info("\tNegotiated compression framing: \(negFraming)")
        }
        let pushedCompression = pushReply.options.compressionAlgorithm
        if let negCompression = pushedCompression {
            log.info("\tNegotiated compression algorithm: \(negCompression)")
        }
        if let negPing = pushReply.options.keepAliveInterval {
            log.info("\tNegotiated keep-alive interval: \(negPing.asTimeString)")
        }
        if let negPingRestart = pushReply.options.keepAliveTimeout {
            log.info("\tNegotiated keep-alive timeout: \(negPingRestart.asTimeString)")
        }

        let bridge: OpenVPN.EncryptionBridge
        do {
            bridge = try OpenVPN.EncryptionBridge(
                pushedCipher ?? configuration.fallbackCipher,
                configuration.fallbackDigest,
                auth,
                sessionId,
                remoteSessionId
            )
        } catch {
            deferStop(.shutdown, error)
            return false
        }

        negotiationKey.dataPath = DataPath(
            encrypter: bridge.encrypter(),
            decrypter: bridge.decrypter(),
            peerId: pushReply.options.peerId ?? PacketPeerIdDisabled,
            compressionFraming: (pushedFraming ?? configuration.fallbackCompressionFraming).native,
            compressionAlgorithm: (pushedCompression ?? configuration.compressionAlgorithm ?? .disabled).native,
            maxPackets: min(link?.packetBufferSize ?? 200, 1000),
            usesReplayProtection: CoreConfiguration.OpenVPN.usesReplayProtection
        )
        return true
    }

    private func internalInvariantError(_ message: String) -> ConnectionError {
        log.error("Internal invariant violated: \(message)")
        return ConnectionError(.internalError, stage: .protocolHandshake, message: message)
    }

    private func linkFailure(operation: String, underlying error: Error) -> ConnectionError {
        let isEstablished = currentKey?.controlState == .connected
        var diagnostics = ["operation": operation]

        if let posixCode = error.posixErrorCode {
            diagnostics["errno"] = String(posixCode)
        }
        return ConnectionError(
            isEstablished ? .connectionLost : .serverUnreachable,
            stage: isEstablished ? .monitoring : .protocolHandshake,
            message: "The OpenVPN transport failed during \(operation).",
            underlying: error,
            diagnostics: diagnostics
        )
    }

    // MARK: Data

    // Ruby: handle_data_pkt
    private func handleDataPackets(_ packets: [Data], key: OpenVPN.SessionKey) {
        controlChannel.addReceivedDataCount(packets.flatCount)
        do {
            guard let decryptedPackets = try key.decrypt(packets: packets) else {
                log.warning("Could not decrypt packets, is SessionKey properly configured (dataPath, peerId)?")
                return
            }
            guard !decryptedPackets.isEmpty else {
                return
            }

            inboundPacketObserver.withLock { $0.observer }?(decryptedPackets)
            tunnel?.writePackets(decryptedPackets, completionHandler: nil)
        } catch {
            if let nativeError = error.asNativeOpenVPNError {
                deferStop(.shutdown, nativeError)
                return
            }
            deferStop(.reconnect, error)
        }
    }

    // Ruby: send_data_pkt
    private func sendDataPackets(_ packets: [Data]) {
        guard let key = currentKey else {
            return
        }
        do {
            guard let encryptedPackets = try key.encrypt(packets: packets) else {
                log.warning("Could not encrypt packets, is SessionKey properly configured (dataPath, peerId)?")
                return
            }
            guard !encryptedPackets.isEmpty else {
                return
            }

            // WARNING: runs in Network.framework queue
            controlChannel.addSentDataCount(encryptedPackets.flatCount)
            let writeLink = UncheckedSendableValue(link)
            link?.writePackets(encryptedPackets) { [weak self] (error) in
                guard let self else {
                    return
                }
                self.queue.async {
                    guard self.link === writeLink.value else {
                        log.warning("Ignoring write from outdated LINK")
                        return
                    }
                    if let error = error {
                        guard !error.isTransientLinkFailure else {
                            self.transientLinkWriteFailures += 1
                            log.debug("Data: Recoverable LINK write failure, dropping packet: \(error)")
                            return
                        }
                        log.error("Data: Failed LINK write during send data: \(error)")
                        self.deferStop(.reconnect, self.linkFailure(operation: "data-write", underlying: error))
                        return
                    }
                }
            }
        } catch {
            if let nativeError = error.asNativeOpenVPNError {
                deferStop(.shutdown, nativeError)
                return
            }
            deferStop(.reconnect, error)
        }
    }

    // MARK: Acks

    private func handleAcks() {
    }

    // Ruby: send_ack
    private func sendAck(for controlPacket: ControlPacket) {
        log.debug("Send ack for received packetId \(controlPacket.packetId)")

        let raw: Data
        do {
            raw = try controlChannel.writeAcks(
                withKey: controlPacket.key,
                ackPacketIds: [controlPacket.packetId],
                ackRemoteSessionId: controlPacket.sessionId
            )
        } catch {
            deferStop(.shutdown, error)
            return
        }

        // WARNING: runs in Network.framework queue
        let writeLink = UncheckedSendableValue(link)
        link?.writePacket(raw) { [weak self] (error) in
            guard let self else {
                return
            }
            self.queue.async {
                guard self.link === writeLink.value else {
                    log.warning("Ignoring write from outdated LINK")
                    return
                }
                if let error = error {
                    guard !error.isTransientLinkFailure else {
                        self.transientLinkWriteFailures += 1
                        log.debug("Recoverable LINK write failure for ack \(controlPacket.packetId), dropping: \(error)")
                        return
                    }
                    log.error("Failed LINK write during send ack for packetId \(controlPacket.packetId): \(error)")
                    self.deferStop(.reconnect, self.linkFailure(operation: "ack-write", underlying: error))
                    return
                }
                log.debug("Ack successfully written to LINK for packetId \(controlPacket.packetId)")
            }
        }
    }

    // MARK: Stop

    private func shouldHandlePackets() -> Bool {
        return !isStopping && !keys.isEmpty
    }

    private func deferStop(_ method: StopMethod, _ error: Error?) {
        guard !isStopping else {
            return
        }
        isStopping = true
        pingTimerGeneration &+= 1
        isStopCompleted = false

        let shouldReconnect: Bool
        switch method {
        case .shutdown:
            shouldReconnect = false
        case .reconnect:
            shouldReconnect = true
        }
        delegate?.sessionWillStop(self, withError: error, shouldReconnect: shouldReconnect)

        // runs on the session queue; guarded against double invocation (the
        // write completion and the fallback timer both call it) and against
        // firing after the session was cleaned up or rebound. `isStopCompleted`
        // is queue-confined like everything else here, so the @Sendable
        // completion captures no mutable local.
        let completion: @Sendable () -> Void = { [weak self] in
            guard let self, !self.isStopCompleted, self.isStopping else {
                return
            }
            self.isStopCompleted = true
            switch method {
            case .shutdown:
                self.doShutdown(error: error)
                self.cleanupCache()

            case .reconnect:
                self.doReconnect(error: error)
            }
        }

        // shut down after sending exit notification if socket is unreliable (normally UDP)
        if let link = link, !link.isReliable {
            do {
                guard let packets = try currentKey?.encrypt(packets: [OpenVPN.OCCPacket.exit.serialized()]) else {
                    completion()
                    return
                }
                link.writePackets(packets) { [weak self] (_) in
                    self?.queue.async {
                        completion()
                    }
                }
                // do not hang in isStopping forever if the write completion never fires
                queue.asyncAfter(deadline: .now() + CoreConfiguration.OpenVPN.tickInterval * 5) {
                    completion()
                }
            } catch {
                completion()
            }
        } else {
            completion()
        }
    }

    private func doShutdown(error: Error?) {
        if let error = error {
            log.error("Trigger shutdown (error: \(error))")
        } else {
            log.info("Trigger shutdown on request")
        }
        stopError = error
        delegate?.sessionDidStop(self, withError: error, shouldReconnect: false)
    }

    private func doReconnect(error: Error?) {
        if let error = error {
            log.error("Trigger reconnection (error: \(error))")
        } else {
            log.info("Trigger reconnection on request")
        }
        stopError = error
        delegate?.sessionDidStop(self, withError: error, shouldReconnect: true)
    }
}

// MARK: ConnectionProbeTransport

extension OpenVPNSession: ConnectionProbeTransport {

    /**
     Injects raw IP packets into the tunnel data path, as if they had been
     read from the tunnel interface. Used by connection validation.
     */
    public func sendProbePackets(_ packets: [Data]) {
        queue.async { [weak self] in
            guard let self, self.shouldHandlePackets() else {
                log.warning("Probe: dropping probe packets, session not ready")
                return
            }
            self.sendDataPackets(packets)
        }
    }

    /**
     Installs an observer for decrypted inbound tunnel packets. Used by
     connection validation.
     */
    public func installInboundPacketObserver(_ observer: @escaping @Sendable ([Data]) -> Void) -> Int {
        inboundPacketObserver.withLock {
            $0.token += 1
            $0.observer = observer
            return $0.token
        }
    }

    /**
     Removes the observer identified by `token`, but only if it is still the
     current one. Used by connection validation.
     */
    public func removeInboundPacketObserver(_ token: Int) {
        inboundPacketObserver.withLock {
            if $0.token == token {
                $0.observer = nil
            }
        }
    }
}
