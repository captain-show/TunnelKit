//
//  ConnectionError.swift
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

/// The stage of the connection lifecycle at which an event occurred.
public enum ConnectionStage: String, Codable, Sendable, CaseIterable {

    /// Parsing and preparing the configuration.
    case preparing

    /// Resolving the remote hostname.
    case dnsResolution

    /// Establishing the transport socket.
    case socketConnection

    /// Performing the protocol handshake.
    case protocolHandshake

    /// Authenticating with the server.
    case authentication

    /// Applying tunnel network settings (addresses, routes, DNS).
    case applyingNetworkSettings

    /// Validating that the tunnel actually carries traffic.
    case validation

    /// Monitoring an established connection.
    case monitoring

    /// Tearing the connection down.
    case disconnection
}

/// A typed, diagnosable error describing why a connection attempt failed
/// or an established connection was lost.
///
/// Carries a stable programmatic `code`, the `stage` at which the failure
/// occurred, an optional `underlying` error and sanitized diagnostic details.
/// Never include secrets (keys, passwords, tokens) in `message` or
/// `diagnostics`.
public struct ConnectionError: Error, Sendable, CustomStringConvertible {

    private enum UserInfoKey {
        static let code = "TunnelKit.ConnectionError.code"

        static let stage = "TunnelKit.ConnectionError.stage"

        static let diagnostics = "TunnelKit.ConnectionError.diagnostics"
    }

    /// A stable programmatic failure code.
    public enum Code: String, Codable, Sendable, CaseIterable {

        /// The configuration is malformed or incomplete.
        case invalidConfiguration

        /// The user or system denied a required permission.
        case permissionDenied

        /// The configuration is valid but not supported on this platform/build.
        case unsupportedConfiguration

        /// The remote server could not be reached at all.
        case serverUnreachable

        /// DNS resolution failed.
        case dnsFailure

        /// The transport connection timed out.
        case connectionTimeout

        /// The protocol handshake did not complete in time.
        case handshakeTimeout

        /// The server rejected the provided credentials.
        case authenticationFailed

        /// Traffic patterns suggest the VPN protocol is being blocked.
        case protocolBlocked

        /// The remote port refused the connection.
        case connectionRefused

        /// The tunnel interface or network settings could not be set up.
        case tunnelSetupFailed

        /// Required routes could not be applied.
        case routeConfigurationFailed

        /// No usable underlying network is available.
        case networkUnavailable

        /// The tunnel came up but failed real-connectivity validation.
        case validationFailed

        /// An established connection was lost.
        case connectionLost

        /// The operation was cancelled (usually by the user).
        case cancelled

        /// An internal invariant was violated; indicates a library bug.
        case internalError
    }

    /// The stable failure code.
    public let code: Code

    /// The lifecycle stage at which the failure occurred.
    public let stage: ConnectionStage

    /// A human-readable, secret-free description.
    public let message: String

    /// The underlying error, if any.
    public let underlying: Error?

    /// Sanitized key-value details useful for diagnostics (never secrets).
    public let diagnostics: [String: String]

    public init(
        _ code: Code,
        stage: ConnectionStage,
        message: String? = nil,
        underlying: Error? = nil,
        diagnostics: [String: String] = [:]
    ) {
        self.code = code
        self.stage = stage
        self.message = message ?? ConnectionError.defaultMessage(for: code)
        self.underlying = underlying
        self.diagnostics = diagnostics
    }

    /**
     Restores a connection error transported as `NSError`, for example across
     the Network Extension XPC boundary.

     The underlying error is intentionally not reconstructed because its
     description is neither stable nor guaranteed to be free of secrets.
     */
    public init?(nsError: NSError) {
        guard nsError.domain == Self.errorDomain,
              let code = Code(errorNumber: nsError.code),
              let stageRawValue = nsError.userInfo[UserInfoKey.stage] as? String,
              let stage = ConnectionStage(rawValue: stageRawValue) else {
            return nil
        }
        if let serializedCode = nsError.userInfo[UserInfoKey.code] as? String,
           serializedCode != code.rawValue {
            return nil
        }

        let diagnostics: [String: String]
        if let serializedDiagnostics = nsError.userInfo[UserInfoKey.diagnostics] as? [String: String] {
            diagnostics = serializedDiagnostics
        } else if let serializedDiagnostics = nsError.userInfo[UserInfoKey.diagnostics] as? [AnyHashable: Any] {
            diagnostics = serializedDiagnostics.reduce(into: [:]) { result, element in
                guard let key = element.key as? String, let value = element.value as? String else {
                    return
                }
                result[key] = value
            }
        } else {
            diagnostics = [:]
        }

        self.init(
            code,
            stage: stage,
            message: nsError.userInfo[NSLocalizedDescriptionKey] as? String,
            diagnostics: diagnostics
        )
    }

    public var description: String {
        var text = "ConnectionError(code: \(code.rawValue), stage: \(stage.rawValue), message: \"\(message)\""
        if let underlying {
            text += ", underlying: \(String(describing: underlying))"
        }
        if !diagnostics.isEmpty {
            text += ", diagnostics: \(diagnostics)"
        }
        text += ")"
        return text
    }

    private static func defaultMessage(for code: Code) -> String {
        switch code {
        case .invalidConfiguration: return "The VPN configuration is invalid or incomplete."
        case .permissionDenied: return "A required permission was denied."
        case .unsupportedConfiguration: return "The VPN configuration is not supported."
        case .serverUnreachable: return "The VPN server is unreachable."
        case .dnsFailure: return "DNS resolution failed."
        case .connectionTimeout: return "The connection timed out."
        case .handshakeTimeout: return "The protocol handshake did not complete in time."
        case .authenticationFailed: return "Authentication with the VPN server failed."
        case .protocolBlocked: return "The VPN protocol appears to be blocked on this network."
        case .connectionRefused: return "The server refused the connection."
        case .tunnelSetupFailed: return "The tunnel could not be set up."
        case .routeConfigurationFailed: return "Tunnel routes could not be configured."
        case .networkUnavailable: return "No network connection is available."
        case .validationFailed: return "The tunnel was established but is not passing traffic."
        case .connectionLost: return "The VPN connection was lost."
        case .cancelled: return "The operation was cancelled."
        case .internalError: return "An internal error occurred."
        }
    }
}

extension ConnectionError.Code {
    fileprivate var errorNumber: Int {
        switch self {
        case .invalidConfiguration: return 1001
        case .permissionDenied: return 1002
        case .unsupportedConfiguration: return 1003
        case .serverUnreachable: return 1004
        case .dnsFailure: return 1005
        case .connectionTimeout: return 1006
        case .handshakeTimeout: return 1007
        case .authenticationFailed: return 1008
        case .protocolBlocked: return 1009
        case .connectionRefused: return 1010
        case .tunnelSetupFailed: return 1011
        case .routeConfigurationFailed: return 1012
        case .networkUnavailable: return 1013
        case .validationFailed: return 1014
        case .connectionLost: return 1015
        case .cancelled: return 1016
        case .internalError: return 1017
        }
    }

    fileprivate init?(errorNumber: Int) {
        switch errorNumber {
        case 1001: self = .invalidConfiguration
        case 1002: self = .permissionDenied
        case 1003: self = .unsupportedConfiguration
        case 1004: self = .serverUnreachable
        case 1005: self = .dnsFailure
        case 1006: self = .connectionTimeout
        case 1007: self = .handshakeTimeout
        case 1008: self = .authenticationFailed
        case 1009: self = .protocolBlocked
        case 1010: self = .connectionRefused
        case 1011: self = .tunnelSetupFailed
        case 1012: self = .routeConfigurationFailed
        case 1013: self = .networkUnavailable
        case 1014: self = .validationFailed
        case 1015: self = .connectionLost
        case 1016: self = .cancelled
        case 1017: self = .internalError
        default: return nil
        }
    }
}

extension ConnectionError: CustomNSError {
    /// Stable domain used when the error crosses Objective-C/XPC boundaries.
    public static let errorDomain = "com.algoritmico.TunnelKit.ConnectionError"

    /// Stable numeric representation of `code`.
    public var errorCode: Int {
        code.errorNumber
    }

    /// Property-list-safe details transported by `NSError`.
    public var errorUserInfo: [String: Any] {
        [
            Self.UserInfoKey.code: code.rawValue,
            Self.UserInfoKey.stage: stage.rawValue,
            Self.UserInfoKey.diagnostics: diagnostics,
            NSLocalizedDescriptionKey: message
        ]
    }
}

extension ConnectionError: LocalizedError {
    public var errorDescription: String? {
        message
    }

    public var failureReason: String? {
        underlying.map { String(describing: $0) }
    }
}
