//
//  WireGuardRuntimeInfoTests.swift
//  TunnelKitWireGuardTests
//
//  Copyright (c) 2026 Davide De Rosa. All rights reserved.
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

import XCTest
import TunnelKitCore
import TunnelKitWireGuardCore
import TunnelKitWireGuardManager

final class WireGuardRuntimeInfoTests: XCTestCase {

    func test_parsesHandshakeAndCounters() throws {
        let dump = """
        private_key=0000000000000000000000000000000000000000000000000000000000000000
        listen_port=51820
        public_key=1111111111111111111111111111111111111111111111111111111111111111
        endpoint=192.0.2.1:51820
        last_handshake_time_sec=1770000000
        last_handshake_time_nsec=123456789
        tx_bytes=1024
        rx_bytes=2048
        persistent_keepalive_interval=25
        """

        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))
        XCTAssertEqual(info.bytesSent, 1024)
        XCTAssertEqual(info.bytesReceived, 2048)
        XCTAssertEqual(
            try XCTUnwrap(info.lastHandshake).timeIntervalSince1970,
            1_770_000_000.1234567,
            accuracy: 0.000_001
        )
        XCTAssertEqual(info.peers.count, 1)
        XCTAssertEqual(info.peers[0].publicKey, String(repeating: "1", count: 64))
        XCTAssertEqual(info.dataCount.received, 2048)
        XCTAssertEqual(info.dataCount.sent, 1024)
    }

    func test_noHandshakeYet_reportsNil() throws {
        // wgTurnOn succeeded but the peer never answered: the exact situation
        // that must NOT be reported as connected
        let dump = """
        public_key=1111111111111111111111111111111111111111111111111111111111111111
        endpoint=192.0.2.1:51820
        last_handshake_time_sec=0
        last_handshake_time_nsec=0
        tx_bytes=444
        rx_bytes=0
        """

        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))
        XCTAssertNil(info.lastHandshake)
        XCTAssertEqual(info.bytesReceived, 0)
    }

    func test_missingCounters_returnsNil() {
        XCTAssertNil(WireGuardRuntimeInfo.from(wireGuardString: ""))
        XCTAssertNil(WireGuardRuntimeInfo.from(wireGuardString: "garbage\nlines\n"))
    }

    func test_partialCounters_areAccepted() throws {
        // a single counter line is enough to consider the dump valid
        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: "rx_bytes=10\n"))
        XCTAssertEqual(info.bytesReceived, 10)
        XCTAssertEqual(info.bytesSent, 0)
        XCTAssertNil(info.lastHandshake)
    }

    func test_malformedValues_areSafe() throws {
        let dump = """
        rx_bytes=not-a-number
        tx_bytes=123
        last_handshake_time_sec=also-bad
        """
        // rx is unparseable (skipped), tx parses; no crash, no false handshake
        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))
        XCTAssertEqual(info.bytesReceived, 0)
        XCTAssertEqual(info.bytesSent, 123)
        XCTAssertNil(info.lastHandshake)
    }

    func test_multiplePeers_preservesPerPeerFactsAndAggregateCompatibility() throws {
        let dump = """
        public_key=aaaa
        last_handshake_time_sec=0
        rx_bytes=100
        tx_bytes=50
        public_key=bbbb
        last_handshake_time_sec=1770000000
        rx_bytes=900
        tx_bytes=450
        """
        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))
        XCTAssertEqual(info.bytesReceived, 1000)
        XCTAssertEqual(info.bytesSent, 500)
        XCTAssertEqual(info.lastHandshake, Date(timeIntervalSince1970: 1_770_000_000))
        XCTAssertEqual(info.peers.count, 2)
        XCTAssertNil(info.peers[0].lastHandshake)
        XCTAssertEqual(info.peers[1].lastHandshake, Date(timeIntervalSince1970: 1_770_000_000))
        let dataCount = try XCTUnwrap(DataCount.from(wireGuardString: dump))
        XCTAssertEqual(dataCount.received, 1_000)
        XCTAssertEqual(dataCount.sent, 500)
    }

    func test_freshness_onlyUsesSelectedPeer() throws {
        let dump = """
        public_key=default-peer
        last_handshake_time_sec=100
        rx_bytes=1
        tx_bytes=1
        public_key=unrelated-peer
        last_handshake_time_sec=995
        rx_bytes=1
        tx_bytes=1
        """
        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))
        let now = Date(timeIntervalSince1970: 1_000)

        XCTAssertFalse(info.hasFreshHandshake(
            peerPublicKeys: ["default-peer"],
            policy: .any,
            now: now,
            maximumAge: 30
        ))
        XCTAssertTrue(info.hasFreshHandshake(
            peerPublicKeys: ["unrelated-peer"],
            policy: .any,
            now: now,
            maximumAge: 30
        ))
    }

    func test_multiPeerPolicy_isAppliedToSelectedPeers() throws {
        let dump = """
        public_key=first
        last_handshake_time_sec=995
        rx_bytes=1
        tx_bytes=1
        public_key=second
        last_handshake_time_sec=100
        rx_bytes=1
        tx_bytes=1
        """
        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))
        let selectedPeers: Set<String> = ["first", "second"]
        let now = Date(timeIntervalSince1970: 1_000)

        XCTAssertTrue(info.hasFreshHandshake(
            peerPublicKeys: selectedPeers,
            policy: .any,
            now: now,
            maximumAge: 30
        ))
        XCTAssertFalse(info.hasFreshHandshake(
            peerPublicKeys: selectedPeers,
            policy: .all,
            now: now,
            maximumAge: 30
        ))
    }

    func test_handshakeMustBelongToCurrentAttempt() throws {
        let dump = """
        public_key=peer
        last_handshake_time_sec=995
        rx_bytes=1
        tx_bytes=1
        """
        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))

        XCTAssertFalse(info.hasFreshHandshake(
            peerPublicKeys: ["peer"],
            policy: .any,
            now: Date(timeIntervalSince1970: 1_000),
            maximumAge: 30,
            notBefore: Date(timeIntervalSince1970: 999)
        ))
    }

    func test_counterAggregationSaturatesOnOverflow() throws {
        let dump = """
        public_key=first
        rx_bytes=\(UInt.max)
        tx_bytes=\(UInt.max)
        public_key=second
        rx_bytes=1
        tx_bytes=1
        """
        let info = try XCTUnwrap(WireGuardRuntimeInfo.from(wireGuardString: dump))
        XCTAssertEqual(info.bytesReceived, UInt.max)
        XCTAssertEqual(info.bytesSent, UInt.max)
    }

    func test_configurationSelectsRoutePeerAndActivatesKeepalive() throws {
        var builder = WireGuard.ConfigurationBuilder()
        try builder.addPeer(Self.key(lastByte: 1), endpoint: "192.0.2.1:51820", allowedIPs: ["0.0.0.0/0"])
        try builder.addPeer(Self.key(lastByte: 2), endpoint: "192.0.2.2:51820", allowedIPs: ["10.0.0.0/8"])
        let configuration = builder.build()

        let defaultPeers = configuration.validationPeerPublicKeys(for: [.gatewayPing])
        let privateRoutePeers = configuration.validationPeerPublicKeys(for: [.ping(host: "10.1.2.3")])
        XCTAssertEqual(defaultPeers.count, 1)
        XCTAssertEqual(privateRoutePeers.count, 1)
        XCTAssertNotEqual(defaultPeers, privateRoutePeers)

        let runtimeConfiguration = configuration.tunnelConfigurationActivatingKeepalive(
            for: defaultPeers,
            interval: 5
        )
        XCTAssertEqual(runtimeConfiguration.peers[0].persistentKeepAlive, 5)
        XCTAssertNil(runtimeConfiguration.peers[1].persistentKeepAlive)
    }

    func test_splitDefaultRouteDoesNotSelectUnrelatedPeer() throws {
        var builder = WireGuard.ConfigurationBuilder()
        try builder.addPeer(
            Self.key(lastByte: 1),
            endpoint: "192.0.2.1:51820",
            allowedIPs: ["0.0.0.0/1", "128.0.0.0/1"]
        )
        try builder.addPeer(
            Self.key(lastByte: 2),
            endpoint: "192.0.2.2:51820",
            allowedIPs: ["10.0.0.0/8"]
        )
        let configuration = builder.build()

        XCTAssertEqual(configuration.validationPeerPublicKeys(for: [.gatewayPing]).count, 1)
    }

    func test_customEncryptedDNSFieldsRoundTripIndependentlyOfDependency() throws {
        var builder = WireGuard.ConfigurationBuilder()
        builder.dnsHTTPSURL = URL(string: "https://dns.example/dns-query")
        builder.dnsTLSServerName = "dns.example"
        let original = builder.build()

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(WireGuard.Configuration.self, from: encoded)
        XCTAssertEqual(decoded.dnsHTTPSURL, original.dnsHTTPSURL)
        XCTAssertEqual(decoded.dnsTLSServerName, original.dnsTLSServerName)
        XCTAssertTrue(decoded.asWgQuickConfig().contains("DNSOverHTTPSURL = https://dns.example/dns-query"))
        XCTAssertTrue(decoded.asWgQuickConfig().contains("DNSOverTLSServerName = dns.example"))
    }

    func test_detailedConnectionErrorRoundTripsAcrossProcessBoundary() throws {
        let detailedError = ConnectionError(
            .handshakeTimeout,
            stage: .protocolHandshake,
            message: "Selected peer did not answer.",
            diagnostics: ["peerCount": "2"]
        )
        let record = WireGuardConnectionError(
            detailedError,
            occurredAt: Date(timeIntervalSince1970: 1_000)
        )

        let data = try JSONEncoder().encode(record)
        let decoded = try JSONDecoder().decode(WireGuardConnectionError.self, from: data)
        XCTAssertEqual(decoded, record)
        XCTAssertEqual(decoded.connectionError.code, .handshakeTimeout)
        XCTAssertEqual(decoded.connectionError.stage, .protocolHandshake)
        XCTAssertEqual(decoded.connectionError.diagnostics["peerCount"], "2")
    }

    private static func key(lastByte: UInt8) -> String {
        var bytes = Data(repeating: 0, count: 32)
        bytes[bytes.index(before: bytes.endIndex)] = lastByte
        return bytes.base64EncodedString()
    }
}
