//
//  ConnectionStrategy.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 6/18/18.
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
import Network
import SwiftyBeaver
import TunnelKitCore
import TunnelKitAppExtension
import TunnelKitOpenVPNCore

private let log = SwiftyBeaver.self

/// Queue-confined endpoint iterator used exclusively from the provider's
/// serial tunnel queue, including DNS completions.
final class ConnectionStrategy: @unchecked Sendable {
    private var remotes: [ResolvedRemote]

    private var currentRemoteIndex: Int

    var currentRemote: ResolvedRemote? {
        guard currentRemoteIndex < remotes.count else {
            return nil
        }
        return remotes[currentRemoteIndex]
    }

    init?(configuration: OpenVPN.Configuration) {
        guard let remotes = configuration.processedRemotes, !remotes.isEmpty else {
            log.error("No remotes provided in configuration")
            return nil
        }
        self.remotes = remotes.map(ResolvedRemote.init)
        currentRemoteIndex = 0
    }

    func hasEndpoints() -> Bool {
        guard let remote = currentRemote else {
            return false
        }
        return !remote.isResolved || remote.currentEndpoint != nil
    }

    @discardableResult
    func tryNextEndpoint() -> Bool {
        guard let remote = currentRemote else {
            return false
        }
        log.debug("Try next endpoint in current remote: \(remote.maskedDescription)")
        if remote.nextEndpoint() {
            return true
        }

        log.debug("Exhausted endpoints, try next remote")
        currentRemoteIndex += 1
        guard let _ = currentRemote else {
            log.debug("Exhausted remotes, giving up")
            return false
        }
        return true
    }

    func createSocket(
        timeout: Int,
        queue: DispatchQueue,
        completionHandler: @escaping @Sendable (Result<GenericSocket, ConnectionError>) -> Void) {
        guard let remote = currentRemote else {
            completionHandler(.failure(ConnectionError(
                .serverUnreachable,
                stage: .socketConnection,
                message: "No usable remote endpoints remain."
            )))
            return
        }
        if remote.isResolved, let endpoint = remote.currentEndpoint {
            log.debug("Pick current endpoint: \(endpoint.maskedDescription)")
            completionHandler(ConnectionStrategy.socket(to: endpoint))
            return
        }

        log.debug("No resolved endpoints, will resort to DNS resolution")
        log.debug("DNS resolve address: \(remote.maskedDescription)")

        remote.resolve(timeout: timeout, queue: queue) { result in
            if case .failure(let error) = result {
                completionHandler(.failure(error))
                return
            }
            guard let endpoint = remote.currentEndpoint else {
                log.error("No endpoints available")
                completionHandler(.failure(ConnectionError(
                    .dnsFailure,
                    stage: .dnsResolution,
                    message: "DNS resolution completed without a usable endpoint."
                )))
                return
            }
            log.debug("Pick current endpoint: \(endpoint.maskedDescription)")
            completionHandler(ConnectionStrategy.socket(to: endpoint))
        }
    }

    /// Builds an `NWConnection`-backed socket for the given resolved endpoint.
    private static func socket(to endpoint: Endpoint) -> Result<GenericSocket, ConnectionError> {
        let host = NWEndpoint.Host(endpoint.address)
        guard endpoint.proto.port != 0, let port = NWEndpoint.Port(rawValue: endpoint.proto.port) else {
            return .failure(ConnectionError(
                .invalidConfiguration,
                stage: .preparing,
                message: "A remote endpoint has an invalid port."
            ))
        }
        let nwEndpoint = NWEndpoint.hostPort(host: host, port: port)

        let isReliable: Bool
        let parameters: NWParameters
        switch endpoint.proto.socketType {
        case .udp, .udp4, .udp6:
            isReliable = false
            parameters = .udp

        case .tcp, .tcp4, .tcp6:
            isReliable = true
            parameters = .tcp
        }

        // This connection runs inside the packet-tunnel provider and must reach
        // the VPN server over the real network. The legacy NWUDPSession/
        // NWTCPConnection transports bypassed the tunnel automatically; a raw
        // NWConnection does not. Once the tunnel installs its default route, an
        // unpinned socket routes back into our own utun (an `.other`-type
        // interface), loses viability, and triggers an endless
        // disconnect/reconnect loop. Excluding `.other` keeps the socket on the
        // physical Wi-Fi/cellular/wired interface and lets it follow the device
        // across network changes (unlike pinning a single fixed interface).
        parameters.prohibitedInterfaceTypes = [.other]

        return .success(NWConnectionSocket(
            endpoint: nwEndpoint,
            parameters: parameters,
            isReliable: isReliable,
            remoteHost: endpoint.address,
            remotePort: endpoint.proto.port
        ))
    }
}
