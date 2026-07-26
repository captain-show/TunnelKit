//
//  AppExtensionTests.swift
//  TunnelKitOpenVPNTests
//
//  Created by Davide De Rosa on 10/23/17.
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

import XCTest
import NetworkExtension
import TunnelKitCore
import TunnelKitOpenVPNCore
@testable import TunnelKitOpenVPNProtocol
import TunnelKitAppExtension
@testable import TunnelKitOpenVPNAppExtension
import TunnelKitManager
import TunnelKitOpenVPNManager

class AppExtensionTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testConfiguration() {
        let bundleIdentifier = "com.example.Provider"
        let appGroup = "group.com.algoritmico.TunnelKit"

        let hostname = "example.com"
        let port: UInt16 = 1234
        let serverAddress = "\(hostname):\(port)"
        let credentials = OpenVPN.Credentials("foo", "bar")

        var builder = OpenVPN.ConfigurationBuilder()
        builder.ca = OpenVPN.CryptoContainer(pem: "abcdef")
        builder.cipher = .aes128cbc
        builder.digest = .sha256
        builder.remotes = [.init(hostname, .init(.udp, port))]
        builder.mtu = 1230

        var cfg = OpenVPN.ProviderConfiguration("", appGroup: appGroup, configuration: builder.build())
        cfg.username = credentials.username
        let proto: NETunnelProviderProtocol
        do {
            proto = try cfg.asTunnelProtocol(withBundleIdentifier: bundleIdentifier, extra: nil)
        } catch {
            XCTFail(error.localizedDescription)
            return
        }

        XCTAssertEqual(proto.providerBundleIdentifier, bundleIdentifier)
        XCTAssertEqual(proto.serverAddress, serverAddress)
        XCTAssertEqual(proto.username, credentials.username)

        guard let pc = proto.providerConfiguration else {
            return
        }

        let ovpn = pc["configuration"] as? [String: Any]
        XCTAssertEqual(pc["appGroup"] as? String, appGroup)
        XCTAssertEqual(pc["shouldDebug"] as? Bool, cfg.shouldDebug)
        XCTAssertEqual(ovpn?["cipher"] as? String, cfg.configuration.cipher?.rawValue)
        XCTAssertEqual(ovpn?["digest"] as? String, cfg.configuration.digest?.rawValue)
        XCTAssertEqual(ovpn?["ca"] as? String, cfg.configuration.ca?.pem)
        XCTAssertEqual(ovpn?["mtu"] as? Int, cfg.configuration.mtu)
        XCTAssertEqual(ovpn?["renegotiatesAfter"] as? TimeInterval, cfg.configuration.renegotiatesAfter)
    }

    func testDetailedConnectionErrorRoundTripsWithoutSecrets() {
        let suiteName = "TunnelKitOpenVPNTests.\(UUID().uuidString)"
        defer { UserDefaults.standard.removePersistentDomain(forName: suiteName) }

        var builder = OpenVPN.ConfigurationBuilder()
        builder.ca = OpenVPN.CryptoContainer(pem: "test-ca")
        let configuration = OpenVPN.ProviderConfiguration(
            "Test",
            appGroup: suiteName,
            configuration: builder.build()
        )
        let connectionError = ConnectionError(
            .validationFailed,
            stage: .validation,
            message: "The end-to-end probe failed.",
            diagnostics: [
                "failedProbes": "dns:example.com",
                "failureDuration": "15.2",
                "gracePeriod": "15.0",
                "operation": "probe",
                "authToken": "must-not-be-persisted",
                "password": "must-not-be-persisted",
                "unknownField": "must-not-be-persisted"
            ]
        )

        configuration._appexSetLastError(
            .connectionValidationFailed,
            connectionError: connectionError
        )

        XCTAssertEqual(configuration.lastError, .connectionValidationFailed)
        XCTAssertEqual(configuration.lastConnectionError?.code, .validationFailed)
        XCTAssertEqual(configuration.lastConnectionError?.stage, .validation)
        XCTAssertEqual(configuration.lastConnectionError?.message, "The end-to-end probe failed.")
        XCTAssertEqual(configuration.lastConnectionError?.diagnostics, [
            "failedProbes": "dns:example.com",
            "failureDuration": "15.2",
            "gracePeriod": "15.0",
            "operation": "probe"
        ])

        configuration._appexSetLastError(nil)
        XCTAssertNil(configuration.lastError)
        XCTAssertNil(configuration.lastConnectionError)
    }

    func testSessionsOwnIndependentCAFiles() throws {
        let cacheURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("TunnelKitOpenVPNTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: cacheURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: cacheURL) }

        var builder = OpenVPN.ConfigurationBuilder()
        builder.ca = OpenVPN.CryptoContainer(pem: "test-ca")
        let configuration = builder.build()
        var firstSession: OpenVPNSession? = try OpenVPNSession(
            queue: DispatchQueue(label: "TunnelKitOpenVPNTests.first-session"),
            configuration: configuration,
            cachesURL: cacheURL
        )
        var secondSession: OpenVPNSession? = try OpenVPNSession(
            queue: DispatchQueue(label: "TunnelKitOpenVPNTests.second-session"),
            configuration: configuration,
            cachesURL: cacheURL
        )

        XCTAssertNotNil(firstSession)
        XCTAssertNotNil(secondSession)
        XCTAssertEqual(try caFiles(in: cacheURL).count, 2)

        firstSession = nil
        XCTAssertEqual(try caFiles(in: cacheURL).count, 1)

        secondSession = nil
        XCTAssertTrue(try caFiles(in: cacheURL).isEmpty)
    }

    func testFullTunnelUsesFallbackDNSWhenServerPushesNone() {
        let localConfiguration = OpenVPN.ConfigurationBuilder().build()
        var remoteBuilder = OpenVPN.ConfigurationBuilder()
        remoteBuilder.ipv4 = IPv4Settings(
            address: "10.8.0.2",
            addressMask: "255.255.255.0",
            defaultGateway: "10.8.0.1"
        )
        remoteBuilder.routingPolicies = [.IPv4]
        let fallbackServers = ["1.1.1.1", "2606:4700:4700::1111"]
        let builder = NetworkSettingsBuilder(
            remoteAddress: "198.51.100.1",
            localOptions: localConfiguration,
            remoteOptions: remoteBuilder.build(),
            fallbackDNSServers: fallbackServers
        )

        XCTAssertEqual(builder.effectiveDNSServers, fallbackServers)
        XCTAssertEqual(builder.build().dnsSettings?.servers, fallbackServers)
    }

    func testEncryptedDNSRejectsImplicitDNSProbeEvenWithExplicitFallback() {
        var options = ConnectionValidationOptions()
        options.policy = .any
        options.probes = [
            .dns(hostname: "example.com", server: nil),
            .ping(host: "1.1.1.1")
        ]

        XCTAssertNotNil(EncryptedDNSValidation.error(dnsProtocol: .https, options: options))

        options.probes = [.ping(host: "1.1.1.1")]
        XCTAssertNil(EncryptedDNSValidation.error(dnsProtocol: .https, options: options))
        XCTAssertNil(EncryptedDNSValidation.error(dnsProtocol: .tls, options: options))
        XCTAssertNil(EncryptedDNSValidation.error(dnsProtocol: .plain, options: .default))
    }

    func testDNSResolver() {
        let exp = expectation(description: "DNS")
        DNSResolver.resolve("www.google.com", timeout: 1000, queue: .main) { result in
            defer {
                exp.fulfill()
            }
            switch result {
            case .success:
                break

            case .failure:
                break
            }
        }
        wait(for: [exp], timeout: 5.0)
    }

    private func caFiles(in directory: URL) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        ).filter {
            $0.lastPathComponent.hasPrefix("ca-") && $0.pathExtension == "pem"
        }
    }

    func testDNSAddressConversion() {
        let testStrings = [
            "0.0.0.0",
            "1.2.3.4",
            "111.222.333.444",
            "1.0.3.255",
            "1.2.255.4",
            "1.2.3.0",
            "255.255.255.255"
        ]
        for expString in testStrings {
            guard let number = DNSResolver.ipv4(fromString: expString) else {
                XCTAssertEqual(expString, "111.222.333.444")
                continue
            }
            let string = DNSResolver.string(fromIPv4: number)
            XCTAssertEqual(string, expString)
        }
    }

    func testEndpointCycling() {
        CoreConfiguration.masksPrivateData = false

        var builder = OpenVPN.ConfigurationBuilder()
        let hostname = "italy.privateinternetaccess.com"
        builder.remotes = [
            .init(hostname, .init(.tcp6, 2222)),
            .init(hostname, .init(.udp, 1111)),
            .init(hostname, .init(.udp4, 3333))
        ]
        guard let strategy = ConnectionStrategy(configuration: builder.build()) else {
            XCTFail("No connection strategy for configuration with remotes")
            return
        }

        let expected = [
            "italy.privateinternetaccess.com:TCP6:2222",
            "italy.privateinternetaccess.com:UDP:1111",
            "italy.privateinternetaccess.com:UDP4:3333"
        ]
        var i = 0
        while strategy.hasEndpoints() {
            guard let remote = strategy.currentRemote else {
                break
            }
            XCTAssertEqual(remote.originalEndpoint.description, expected[i])
            i += 1
            guard strategy.tryNextEndpoint() else {
                break
            }
        }
    }

//    func testEndpointCycling4() {
//        CoreConfiguration.masksPrivateData = false
//
//        var builder = OpenVPN.ConfigurationBuilder()
//        builder.hostname = "italy.privateinternetaccess.com"
//        builder.endpointProtocols = [
//            EndpointProtocol(.tcp4, 2222),
//        ]
//        let strategy = ConnectionStrategy(
//            configuration: builder.build(),
//            resolvedRecords: [
//                DNSRecord(address: "111:bbbb:ffff::eeee", isIPv6: true),
//                DNSRecord(address: "11.22.33.44", isIPv6: false),
//            ]
//        )
//
//        let expected = [
//            "11.22.33.44:TCP4:2222"
//        ]
//        var i = 0
//        while strategy.hasEndpoint() {
//            let endpoint = strategy.currentEndpoint()
//            XCTAssertEqual(endpoint.description, expected[i])
//            i += 1
//            strategy.tryNextEndpoint()
//        }
//    }
//
//    func testEndpointCycling6() {
//        CoreConfiguration.masksPrivateData = false
//
//        var builder = OpenVPN.ConfigurationBuilder()
//        builder.hostname = "italy.privateinternetaccess.com"
//        builder.endpointProtocols = [
//            EndpointProtocol(.udp6, 2222),
//        ]
//        let strategy = ConnectionStrategy(
//            configuration: builder.build(),
//            resolvedRecords: [
//                DNSRecord(address: "111:bbbb:ffff::eeee", isIPv6: true),
//                DNSRecord(address: "11.22.33.44", isIPv6: false),
//            ]
//        )
//
//        let expected = [
//            "111:bbbb:ffff::eeee:UDP6:2222"
//        ]
//        var i = 0
//        while strategy.hasEndpoint() {
//            let endpoint = strategy.currentEndpoint()
//            XCTAssertEqual(endpoint.description, expected[i])
//            i += 1
//            strategy.tryNextEndpoint()
//        }
//    }
}
