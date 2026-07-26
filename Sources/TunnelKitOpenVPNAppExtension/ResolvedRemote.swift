//
//  ResolvedRemote.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 3/3/22.
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
import SwiftyBeaver

private let log = SwiftyBeaver.self

/// `@unchecked Sendable`: instances are created and mutated only on the tunnel
/// queue passed to `resolve(timeout:queue:)`; the DNS completion is delivered
/// back on that same queue, so `isResolved`/`resolvedEndpoints`/`currentEndpointIndex`
/// are never touched concurrently.
final class ResolvedRemote: CustomStringConvertible, @unchecked Sendable {
    let originalEndpoint: Endpoint

    private(set) var isResolved: Bool

    private(set) var resolvedEndpoints: [Endpoint]

    private var currentEndpointIndex: Int

    var currentEndpoint: Endpoint? {
        guard currentEndpointIndex < resolvedEndpoints.count else {
            return nil
        }
        return resolvedEndpoints[currentEndpointIndex]
    }

    init(_ originalEndpoint: Endpoint) {
        self.originalEndpoint = originalEndpoint
        isResolved = false
        resolvedEndpoints = []
        currentEndpointIndex = 0
    }

    func nextEndpoint() -> Bool {
        currentEndpointIndex += 1
        return currentEndpointIndex < resolvedEndpoints.count
    }

    func resolve(
        timeout: Int,
        queue: DispatchQueue,
        completionHandler: @escaping @Sendable (Result<Void, ConnectionError>) -> Void
    ) {
        DNSResolver.resolve(
            originalEndpoint.address,
            timeout: timeout,
            queue: queue,
            family: Self.requiredFamily(for: originalEndpoint.proto)
        ) { [weak self] result in
            guard let self else {
                completionHandler(.failure(ConnectionError(
                    .cancelled,
                    stage: .dnsResolution,
                    message: "DNS resolution was cancelled because its remote was released."
                )))
                return
            }
            completionHandler(self.handleResult(result))
        }
    }

    private func handleResult(_ result: Result<[DNSRecord], Error>) -> Result<Void, ConnectionError> {
        switch result {
        case .success(let records):
            log.debug("DNS resolved addresses: \(records.map { $0.address }.maskedDescription)")
            isResolved = true
            resolvedEndpoints = unrolledEndpoints(records: records)
            currentEndpointIndex = 0
            guard !resolvedEndpoints.isEmpty else {
                return .failure(ConnectionError(
                    .dnsFailure,
                    stage: .dnsResolution,
                    message: "DNS returned no addresses compatible with the configured transport."
                ))
            }
            return .success(())

        case .failure(let error):
            log.error("DNS resolution failed: \(error)")
            isResolved = false
            resolvedEndpoints = []
            currentEndpointIndex = 0
            return .failure(ConnectionError(
                .dnsFailure,
                stage: .dnsResolution,
                underlying: error
            ))
        }
    }

    /// Maps a transport's socket type to the address family it can dial, so the
    /// resolver does not settle early on a family this endpoint cannot use.
    private static func requiredFamily(for proto: EndpointProtocol) -> DNSAddressFamily {
        switch proto.socketType {
        case .udp4, .tcp4:
            return .ipv4

        case .udp6, .tcp6:
            return .ipv6

        case .udp, .tcp:
            return .any
        }
    }

    private func unrolledEndpoints(records: [DNSRecord]) -> [Endpoint] {
        let endpoints = records.filter {
            $0.isCompatible(withProtocol: originalEndpoint.proto)
        }.map {
            Endpoint($0.address, originalEndpoint.proto)
        }
        log.debug("Unrolled endpoints: \(endpoints.maskedDescription)")
        return endpoints
    }

    // MARK: CustomStringConvertible

    var description: String {
        "{\(originalEndpoint.maskedDescription), resolved: \(resolvedEndpoints.maskedDescription)}"
    }
}

private extension DNSRecord {
    func isCompatible(withProtocol proto: EndpointProtocol) -> Bool {
        if isIPv6 {
            return proto.socketType != .udp4 && proto.socketType != .tcp4
        } else {
            return proto.socketType != .udp6 && proto.socketType != .tcp6
        }
    }
}
