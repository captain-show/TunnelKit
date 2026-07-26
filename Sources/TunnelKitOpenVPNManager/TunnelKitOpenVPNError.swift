//
//  TunnelKitOpenVPNError.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 11/8/21.
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
import TunnelKitCore
import TunnelKitOpenVPNCore

/// The errors causing a tunnel disconnection.
public enum TunnelKitOpenVPNError: String, Error, Sendable {

    /// Socket endpoint could not be resolved.
    case dnsFailure

    /// No more endpoints available to try.
    case exhaustedEndpoints

    /// Socket failed to reach active state.
    case socketActivity

    /// Credentials authentication failed.
    case authentication

    /// TLS could not be initialized (e.g. malformed CA or client PEMs).
    case tlsInitialization

    /// TLS server verification failed.
    case tlsServerVerification

    /// TLS handshake failed.
    case tlsHandshake

    /// The encryption logic could not be initialized (e.g. PRNG, algorithms).
    case encryptionInitialization

    /// Data encryption/decryption failed.
    case encryptionData

    /// The LZO engine failed.
    case lzo

    /// Server uses an unsupported compression algorithm.
    case serverCompression

    /// Tunnel timed out.
    case timeout

    /// An error occurred at the link level.
    case linkError

    /// Network routing information is missing or incomplete.
    case routing

    /// The current network changed (e.g. switched from WiFi to data connection).
    case networkChanged

    /// Default gateway could not be attained.
    case gatewayUnattainable

    /// Remove server has shut down.
    case serverShutdown

    /// The server replied in an unexpected way.
    case unexpectedReply

    /// The tunnel was set up but failed real-connectivity validation.
    case connectionValidationFailed

    /// The protocol handshake did not complete in time.
    case handshakeTimeout

    /// The remote server could not be reached.
    case serverUnreachable

    /// The operation was cancelled.
    case cancelled

    /// An internal invariant was violated (library bug).
    case internalError
}

/// Persistable, secret-free details for the last OpenVPN connection error.
///
/// The legacy `TunnelKitOpenVPNError` remains available for source and storage
/// compatibility. This snapshot additionally preserves the connection stage
/// and safe diagnostics across the app/extension process boundary.
public struct OpenVPNConnectionError: Codable, Equatable, Sendable {
    public let code: ConnectionError.Code

    public let stage: ConnectionStage

    public let message: String

    public let diagnostics: [String: String]

    public let occurredAt: Date

    public init(_ error: ConnectionError, occurredAt: Date = Date()) {
        code = error.code
        stage = error.stage
        message = error.message
        diagnostics = Self.sanitizedDiagnostics(error.diagnostics)
        self.occurredAt = occurredAt
    }

    public var connectionError: ConnectionError {
        ConnectionError(code, stage: stage, message: message, diagnostics: diagnostics)
    }

    private static func sanitizedDiagnostics(_ diagnostics: [String: String]) -> [String: String] {
        // Persist only fields emitted by TunnelKit itself. An allowlist keeps a
        // future caller from accidentally crossing process boundaries with a
        // token, credential, endpoint key or other secret.
        let allowedKeys: Set<String> = [
            "attemptsPerProbe",
            "deadline",
            "failedProbes",
            "failureDuration",
            "gracePeriod",
            "invalidFields",
            "legacyCode",
            "maxDuration",
            "operation",
            "parameter",
            "phase",
            "policy",
            "probeIndex",
            "reason",
            "sawInboundTraffic",
            "transport"
        ]
        return diagnostics.reduce(into: [:]) { result, entry in
            guard allowedKeys.contains(entry.key) else {
                return
            }
            // Bound app-group storage and log exposure even for safe fields.
            result[entry.key] = String(entry.value.prefix(512))
        }
    }
}
