//
//  WireGuardRuntimeInfo.swift
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
import TunnelKitCore

/// Peer facts parsed from the WireGuard runtime configuration (wg UAPI format).
public struct WireGuardRuntimeInfo: Equatable, Sendable {

    public struct Peer: Equatable, Sendable {

        /// Hex-encoded public key from the UAPI dump. It is nil only for a
        /// malformed/partial dump that contains counters before a peer key.
        public let publicKey: String?

        public let bytesReceived: UInt

        public let bytesSent: UInt

        public let lastHandshake: Date?

        public init(publicKey: String?, bytesReceived: UInt, bytesSent: UInt, lastHandshake: Date?) {
            self.publicKey = publicKey
            self.bytesReceived = bytesReceived
            self.bytesSent = bytesSent
            self.lastHandshake = lastHandshake
        }
    }

    /// Runtime facts kept per peer. Connection validation must use this array
    /// instead of the aggregate timestamp so an unrelated healthy peer cannot
    /// hide a dead default-route peer.
    public let peers: [Peer]

    /// Bytes received from the peer.
    public let bytesReceived: UInt

    /// Bytes sent to the peer.
    public let bytesSent: UInt

    /// The time of the most recent completed handshake, nil if none yet.
    public let lastHandshake: Date?

    /// Received/sent counters as a `DataCount`.
    public var dataCount: DataCount {
        DataCount(bytesReceived, bytesSent)
    }

    public init(
        bytesReceived: UInt,
        bytesSent: UInt,
        lastHandshake: Date?,
        peers: [Peer] = []
    ) {
        self.bytesReceived = bytesReceived
        self.bytesSent = bytesSent
        self.lastHandshake = lastHandshake
        self.peers = peers
    }

    /**
     Parses the runtime configuration string returned by
     `WireGuardAdapter.getRuntimeConfiguration`.

     - Parameter string: The "wg show"-style configuration dump.
     - Returns: The parsed info, or nil if the counters are missing.
     */
    public static func from(wireGuardString string: String) -> WireGuardRuntimeInfo? {
        struct PeerBuilder {
            var publicKey: String?
            var bytesReceived: UInt = 0
            var bytesSent: UInt = 0
            var handshakeSeconds: Int64?
            var handshakeNanoseconds: Int64 = 0
            var sawCounter = false

            var isEmpty: Bool {
                publicKey == nil && !sawCounter && handshakeSeconds == nil
            }

            func build() -> Peer {
                let handshake: Date?
                if let handshakeSeconds, handshakeSeconds > 0,
                   (0..<1_000_000_000).contains(handshakeNanoseconds) {
                    handshake = Date(
                        timeIntervalSince1970: TimeInterval(handshakeSeconds)
                            + TimeInterval(handshakeNanoseconds) / 1_000_000_000
                    )
                } else {
                    handshake = nil
                }
                return Peer(
                    publicKey: publicKey,
                    bytesReceived: bytesReceived,
                    bytesSent: bytesSent,
                    lastHandshake: handshake
                )
            }
        }

        var builders: [PeerBuilder] = []
        var current = PeerBuilder()

        func flushCurrentPeer() {
            guard !current.isEmpty else {
                return
            }
            builders.append(current)
            current = PeerBuilder()
        }

        for rawLine in string.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            if line.hasPrefix("public_key=") {
                flushCurrentPeer()
                current.publicKey = line.valueOfPrefix("public_key=", as: String.self)
            } else if let value = line.valueOfPrefix("rx_bytes=", as: UInt.self) {
                current.bytesReceived = value
                current.sawCounter = true
            } else if let value = line.valueOfPrefix("tx_bytes=", as: UInt.self) {
                current.bytesSent = value
                current.sawCounter = true
            } else if let value = line.valueOfPrefix("last_handshake_time_sec=", as: Int64.self) {
                current.handshakeSeconds = value
            } else if let value = line.valueOfPrefix("last_handshake_time_nsec=", as: Int64.self) {
                current.handshakeNanoseconds = value
            }
        }
        flushCurrentPeer()

        guard builders.contains(where: { $0.sawCounter }) else {
            return nil
        }

        let peers = builders.map { $0.build() }
        let totalReceived = peers.reduce(into: UInt(0)) { total, peer in
            total = total.saturatingAdding(peer.bytesReceived)
        }
        let totalSent = peers.reduce(into: UInt(0)) { total, peer in
            total = total.saturatingAdding(peer.bytesSent)
        }
        let latestHandshake = peers.compactMap(\.lastHandshake).max()
        return WireGuardRuntimeInfo(
            bytesReceived: totalReceived,
            bytesSent: totalSent,
            lastHandshake: latestHandshake,
            peers: peers
        )
    }

    /// Returns whether the selected peers have a recent handshake. `policy`
    /// applies to the selected key set, never to unrelated peers.
    public func hasFreshHandshake(
        peerPublicKeys: Set<String>,
        policy: ConnectionValidationOptions.Policy,
        now: Date,
        maximumAge: TimeInterval,
        notBefore: Date? = nil
    ) -> Bool {
        guard !peerPublicKeys.isEmpty, maximumAge > 0 else {
            return false
        }

        let peersByKey = peers.reduce(into: [String: Peer]()) { result, peer in
            guard let publicKey = peer.publicKey else {
                return
            }
            result[publicKey.lowercased()] = peer
        }

        func isFresh(_ publicKey: String) -> Bool {
            guard let handshake = peersByKey[publicKey.lowercased()]?.lastHandshake else {
                return false
            }
            // Allow a tiny clock/serialization skew, but reject timestamps
            // materially in the future or belonging to an earlier attempt.
            guard handshake <= now.addingTimeInterval(2),
                  now.timeIntervalSince(handshake) <= maximumAge else {
                return false
            }
            if let notBefore,
               handshake < notBefore.addingTimeInterval(-2) {
                return false
            }
            return true
        }

        switch policy {
        case .any:
            return peerPublicKeys.contains(where: isFresh)
        case .all:
            return peerPublicKeys.allSatisfy(isFresh)
        }
    }
}

private extension String {
    func valueOfPrefix<T: LosslessStringConvertible>(_ prefixKey: String, as type: T.Type) -> T? {
        guard hasPrefix(prefixKey) else {
            return nil
        }
        return T(String(dropFirst(prefixKey.count)))
    }
}

private extension UInt {
    func saturatingAdding(_ other: UInt) -> UInt {
        let (sum, overflow) = addingReportingOverflow(other)
        return overflow ? .max : sum
    }
}
