//
//  Configuration.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 11/23/21.
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

import Foundation
import TunnelKitCore
// WireGuardKit predates Sendable annotations; its value types (TunnelConfiguration,
// IPAddressRange, etc.) are immutable and safe to share. Import it as
// pre-concurrency so their use does not raise spurious Sendable warnings.
@preconcurrency import WireGuardKit
import Network
import NetworkExtension

public protocol WireGuardConfigurationProviding {
    var interface: InterfaceConfiguration { get }

    var peers: [PeerConfiguration] { get }

    var privateKey: String { get }

    var publicKey: String { get }

    var addresses: [String] { get }

    var dnsServers: [String] { get }

    var dnsSearchDomains: [String] { get }

    var dnsHTTPSURL: URL? { get }

    var dnsTLSServerName: String? { get }

    var mtu: UInt16? { get }

    var peersCount: Int { get }

    func publicKey(ofPeer peerIndex: Int) -> String

    func preSharedKey(ofPeer peerIndex: Int) -> String?

    func endpoint(ofPeer peerIndex: Int) -> String?

    func allowedIPs(ofPeer peerIndex: Int) -> [String]

    func keepAlive(ofPeer peerIndex: Int) -> UInt16?
}

extension WireGuard {
    public struct ConfigurationBuilder: WireGuardConfigurationProviding {
        private static let defaultGateway4 = IPAddressRange(from: "0.0.0.0/0")!

        private static let defaultGateway6 = IPAddressRange(from: "::/0")!

        public private(set) var interface: InterfaceConfiguration

        public private(set) var peers: [PeerConfiguration]

        private var dnsHTTPSURLValue: URL?

        private var dnsTLSServerNameValue: String?

        public init() {
            self.init(PrivateKey())
        }

        public init(_ base64PrivateKey: String) throws {
            guard let privateKey = PrivateKey(base64Key: base64PrivateKey) else {
                throw WireGuard.ConfigurationError.interfaceHasInvalidPrivateKey(base64PrivateKey)
            }
            self.init(privateKey)
        }

        private init(_ privateKey: PrivateKey) {
            interface = InterfaceConfiguration(privateKey: privateKey)
            peers = []
            dnsHTTPSURLValue = nil
            dnsTLSServerNameValue = nil
        }

        public init(
            _ tunnelConfiguration: TunnelConfiguration,
            dnsHTTPSURL: URL? = nil,
            dnsTLSServerName: String? = nil
        ) {
            interface = tunnelConfiguration.interface
            peers = tunnelConfiguration.peers
            dnsHTTPSURLValue = dnsHTTPSURL
            dnsTLSServerNameValue = dnsTLSServerName
        }

        // MARK: WireGuardConfigurationProviding

        public var privateKey: String {
            get {
                interface.privateKey.base64Key
            }
            set {
                guard let key = PrivateKey(base64Key: newValue) else {
                    return
                }
                interface.privateKey = key
            }
        }

        public var addresses: [String] {
            get {
                interface.addresses.map(\.stringRepresentation)
            }
            set {
                interface.addresses = newValue.compactMap(IPAddressRange.init)
            }
        }

        public var dnsServers: [String] {
            get {
                interface.dns.map(\.stringRepresentation)
            }
            set {
                interface.dns = newValue.compactMap(DNSServer.init)
            }
        }

        public var dnsSearchDomains: [String] {
            get {
                interface.dnsSearch
            }
            set {
                interface.dnsSearch = newValue
            }
        }

        public var dnsHTTPSURL: URL? {
            get {
                dnsHTTPSURLValue
            }
            set {
                dnsHTTPSURLValue = newValue
            }
        }

        public var dnsTLSServerName: String? {
            get {
                dnsTLSServerNameValue
            }
            set {
                dnsTLSServerNameValue = newValue
            }
        }

        public var mtu: UInt16? {
            get {
                interface.mtu
            }
            set {
                interface.mtu = newValue
            }
        }

        // MARK: Modification

        public mutating func addPeer(_ base64PublicKey: String, endpoint: String, allowedIPs: [String] = []) throws {
            guard let publicKey = PublicKey(base64Key: base64PublicKey) else {
                throw WireGuard.ConfigurationError.peerHasInvalidPublicKey(base64PublicKey)
            }
            var peer = PeerConfiguration(publicKey: publicKey)
            peer.endpoint = Endpoint(from: endpoint)
            peer.allowedIPs = allowedIPs.compactMap(IPAddressRange.init)
            peers.append(peer)
        }

        public mutating func setPreSharedKey(_ base64Key: String, ofPeer peerIndex: Int) throws {
            guard let preSharedKey = PreSharedKey(base64Key: base64Key) else {
                throw WireGuard.ConfigurationError.peerHasInvalidPreSharedKey(base64Key)
            }
            peers[peerIndex].preSharedKey = preSharedKey
        }

        public mutating func addDefaultGatewayIPv4(toPeer peerIndex: Int) {
            peers[peerIndex].allowedIPs.append(Self.defaultGateway4)
        }

        public mutating func addDefaultGatewayIPv6(toPeer peerIndex: Int) {
            peers[peerIndex].allowedIPs.append(Self.defaultGateway6)
        }

        public mutating func removeDefaultGatewayIPv4(fromPeer peerIndex: Int) {
            peers[peerIndex].allowedIPs.removeAll {
                $0 == Self.defaultGateway4
            }
        }

        public mutating func removeDefaultGatewayIPv6(fromPeer peerIndex: Int) {
            peers[peerIndex].allowedIPs.removeAll {
                $0 == Self.defaultGateway6
            }
        }

        public mutating func removeDefaultGateways(fromPeer peerIndex: Int) {
            peers[peerIndex].allowedIPs.removeAll {
                $0 == Self.defaultGateway4 || $0 == Self.defaultGateway6
            }
        }

        public mutating func removeAllDefaultGateways() {
            peers.indices.forEach {
                removeDefaultGateways(fromPeer: $0)
            }
        }

        public mutating func addAllowedIP(_ allowedIP: String, toPeer peerIndex: Int) {
            guard let addr = IPAddressRange(from: allowedIP) else {
                return
            }
            peers[peerIndex].allowedIPs.append(addr)
        }

        public mutating func removeAllowedIP(_ allowedIP: String, fromPeer peerIndex: Int) {
            guard let addr = IPAddressRange(from: allowedIP) else {
                return
            }
            peers[peerIndex].allowedIPs.removeAll {
                $0 == addr
            }
        }

        public mutating func setKeepAlive(_ keepAlive: UInt16, forPeer peerIndex: Int) {
            peers[peerIndex].persistentKeepAlive = keepAlive
        }

        public func build() -> Configuration {
            let tunnelConfiguration = TunnelConfiguration(name: nil, interface: interface, peers: peers)
            return Configuration(
                tunnelConfiguration: tunnelConfiguration,
                dnsHTTPSURL: dnsHTTPSURLValue,
                dnsTLSServerName: dnsTLSServerNameValue
            )
        }
    }

    public struct Configuration: Codable, Equatable, WireGuardConfigurationProviding {
        public let tunnelConfiguration: TunnelConfiguration

        public let dnsHTTPSURL: URL?

        public let dnsTLSServerName: String?

        public var interface: InterfaceConfiguration {
            tunnelConfiguration.interface
        }

        public var peers: [PeerConfiguration] {
            tunnelConfiguration.peers
        }

        public init(
            tunnelConfiguration: TunnelConfiguration,
            dnsHTTPSURL: URL? = nil,
            dnsTLSServerName: String? = nil
        ) {
            self.tunnelConfiguration = tunnelConfiguration
            self.dnsHTTPSURL = dnsHTTPSURL
            self.dnsTLSServerName = dnsTLSServerName
        }

        public func builder() -> WireGuard.ConfigurationBuilder {
            WireGuard.ConfigurationBuilder(
                tunnelConfiguration,
                dnsHTTPSURL: dnsHTTPSURL,
                dnsTLSServerName: dnsTLSServerName
            )
        }

        // MARK: WireGuardConfigurationProviding

        public var privateKey: String {
            interface.privateKey.base64Key
        }

        public var publicKey: String {
            interface.privateKey.publicKey.base64Key
        }

        public var addresses: [String] {
            interface.addresses.map(\.stringRepresentation)
        }

        public var dnsServers: [String] {
            interface.dns.map(\.stringRepresentation)
        }

        public var dnsSearchDomains: [String] {
            interface.dnsSearch
        }

        public var mtu: UInt16? {
            interface.mtu
        }

        // MARK: Codable

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let wg = try container.decode(String.self)
            var dnsHTTPSURL: URL?
            var dnsTLSServerName: String?
            let tunnelConfiguration = try TunnelConfiguration(
                fromTunnelKitWgQuickConfig: wg,
                called: nil,
                dnsHTTPSURL: &dnsHTTPSURL,
                dnsTLSServerName: &dnsTLSServerName
            )
            self.init(
                tunnelConfiguration: tunnelConfiguration,
                dnsHTTPSURL: dnsHTTPSURL,
                dnsTLSServerName: dnsTLSServerName
            )
        }

        public func encode(to encoder: Encoder) throws {
            let wg = tunnelConfiguration.asTunnelKitWgQuickConfig(
                dnsHTTPSURL: dnsHTTPSURL,
                dnsTLSServerName: dnsTLSServerName
            )
            var container = encoder.singleValueContainer()
            try container.encode(wg)
        }
    }
}

extension WireGuardConfigurationProviding {
    public var publicKey: String {
        interface.privateKey.publicKey.base64Key
    }

    public var peersCount: Int {
        peers.count
    }

    public func publicKey(ofPeer peerIndex: Int) -> String {
        peers[peerIndex].publicKey.base64Key
    }

    public func preSharedKey(ofPeer peerIndex: Int) -> String? {
        peers[peerIndex].preSharedKey?.base64Key
    }

    public func endpoint(ofPeer peerIndex: Int) -> String? {
        peers[peerIndex].endpoint?.stringRepresentation
    }

    public func allowedIPs(ofPeer peerIndex: Int) -> [String] {
        peers[peerIndex].allowedIPs.map(\.stringRepresentation)
    }

    public func keepAlive(ofPeer peerIndex: Int) -> UInt16? {
        peers[peerIndex].persistentKeepAlive
    }
}

extension WireGuard.Configuration {

    /// Hex keys of the peers that carry the configured validation traffic.
    /// Route lookup uses longest-prefix matching; a healthy unrelated peer is
    /// therefore never allowed to validate a dead default-route peer.
    public func validationPeerPublicKeys(
        for probes: [ConnectionValidationOptions.Probe]
    ) -> Set<String> {
        var selectedKeys = Set<String>()

        for probe in probes {
            switch probe {
            case .gatewayPing:
                let defaultPeers = peers.filter(\.routesDefaultAddressSpace)
                let peersToUse = defaultPeers.isEmpty
                    ? peers.filter { $0.endpoint != nil }
                    : defaultPeers
                selectedKeys.formUnion(peersToUse.map { $0.publicKey.hexKey.lowercased() })

            case .ping(let host):
                selectedKeys.formUnion(peerPublicKeys(routing: host))

            case .dns(_, let server):
                let target = server ?? dnsServers.first
                if let target {
                    selectedKeys.formUnion(peerPublicKeys(routing: target))
                }
            }
        }

        return selectedKeys
    }

    /// Returns a copy with an active keepalive on selected peers. This makes a
    /// brand-new, otherwise idle profile initiate a WireGuard handshake and
    /// provides ongoing liveness evidence without changing the saved profile.
    public func tunnelConfigurationActivatingKeepalive(
        for peerPublicKeys: Set<String>,
        interval: UInt16
    ) -> TunnelConfiguration {
        guard interval > 0 else {
            return tunnelConfiguration
        }

        let updatedPeers = peers.map { peer -> PeerConfiguration in
            guard peerPublicKeys.contains(peer.publicKey.hexKey.lowercased()) else {
                return peer
            }
            var updatedPeer = peer
            if let currentInterval = updatedPeer.persistentKeepAlive {
                if currentInterval == 0 || currentInterval > interval {
                    updatedPeer.persistentKeepAlive = interval
                }
            } else {
                updatedPeer.persistentKeepAlive = interval
            }
            return updatedPeer
        }
        return TunnelConfiguration(
            name: tunnelConfiguration.name,
            interface: tunnelConfiguration.interface,
            peers: updatedPeers
        )
    }

    private func peerPublicKeys(routing host: String) -> Set<String> {
        let targetAddress: IPAddress?
        if let address = IPv4Address(host) {
            targetAddress = address
        } else if let address = IPv6Address(host) {
            targetAddress = address
        } else {
            // A hostname cannot be matched against AllowedIPs before DNS
            // resolution. Its resolution follows the default route.
            targetAddress = nil
        }

        guard let targetAddress else {
            return Set(peers.filter(\.routesDefaultAddressSpace)
                .map { $0.publicKey.hexKey.lowercased() })
        }

        var longestPrefix: UInt8?
        var selectedKeys = Set<String>()
        for peer in peers {
            for route in peer.allowedIPs where route.contains(targetAddress) {
                if let currentLongestPrefix = longestPrefix {
                    if route.networkPrefixLength > currentLongestPrefix {
                        longestPrefix = route.networkPrefixLength
                        selectedKeys = [peer.publicKey.hexKey.lowercased()]
                    } else if route.networkPrefixLength == currentLongestPrefix {
                        selectedKeys.insert(peer.publicKey.hexKey.lowercased())
                    }
                } else {
                    longestPrefix = route.networkPrefixLength
                    selectedKeys = [peer.publicKey.hexKey.lowercased()]
                }
            }
        }
        return selectedKeys
    }
}

private extension PeerConfiguration {
    var routesDefaultAddressSpace: Bool {
        if allowedIPs.contains(where: { $0.networkPrefixLength == 0 }) {
            return true
        }

        let halves = allowedIPs.filter { $0.networkPrefixLength == 1 }
            .map { $0.maskedAddress().rawValue }
        let ipv4Lower = Data([0, 0, 0, 0])
        let ipv4Upper = Data([128, 0, 0, 0])
        if halves.contains(ipv4Lower), halves.contains(ipv4Upper) {
            return true
        }

        let ipv6Lower = Data(repeating: 0, count: 16)
        var ipv6Upper = ipv6Lower
        ipv6Upper[ipv6Upper.startIndex] = 0x80
        return halves.contains(ipv6Lower) && halves.contains(ipv6Upper)
    }
}

private extension IPAddressRange {
    func contains(_ candidate: IPAddress) -> Bool {
        let routeBytes = address.rawValue
        let candidateBytes = candidate.rawValue
        guard routeBytes.count == candidateBytes.count else {
            return false
        }

        let fullBytes = Int(networkPrefixLength / 8)
        let remainingBits = Int(networkPrefixLength % 8)
        guard routeBytes.prefix(fullBytes) == candidateBytes.prefix(fullBytes) else {
            return false
        }
        guard remainingBits > 0 else {
            return true
        }

        let mask = UInt8.max << UInt8(8 - remainingBits)
        return routeBytes[fullBytes] & mask == candidateBytes[fullBytes] & mask
    }
}
