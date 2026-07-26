// SPDX-License-Identifier: MIT
// Copyright © 2018-2021 WireGuard LLC. All Rights Reserved.

import Foundation
import TunnelKitCore

public enum TunnelKitWireGuardError: String, Error, Codable, LocalizedError, Sendable {
    case savedProtocolConfigurationIsInvalid
    case dnsResolutionFailure
    case couldNotStartBackend
    case couldNotDetermineFileDescriptor
    case couldNotSetNetworkSettings

    /// The WireGuard handshake with the peer did not complete in time
    /// (server unreachable, port blocked, or invalid keys).
    case handshakeTimeout

    /// The tunnel was set up but failed real-connectivity validation.
    case connectionValidationFailed

    /// The connection attempt was superseded or torn down mid-flight.
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .savedProtocolConfigurationIsInvalid:
            "The saved WireGuard configuration is invalid."
        case .dnsResolutionFailure:
            "A WireGuard peer endpoint could not be resolved."
        case .couldNotStartBackend:
            "The WireGuard backend could not be started."
        case .couldNotDetermineFileDescriptor:
            "The WireGuard tunnel interface could not be located."
        case .couldNotSetNetworkSettings:
            "The WireGuard network settings could not be applied."
        case .handshakeTimeout:
            "The selected WireGuard peer did not complete a handshake in time."
        case .connectionValidationFailed:
            "The WireGuard tunnel failed connectivity validation."
        case .cancelled:
            "The WireGuard connection attempt was cancelled."
        }
    }
}

/// Persistable, secret-free details for the last WireGuard connection error.
/// Unlike `TunnelKitWireGuardError`, this record preserves the lifecycle stage
/// and diagnostics across the app/extension process boundary.
public struct WireGuardConnectionError: Codable, Equatable, Sendable {
    public let code: ConnectionError.Code
    public let stage: ConnectionStage
    public let message: String
    public let diagnostics: [String: String]
    public let occurredAt: Date

    public init(_ error: ConnectionError, occurredAt: Date = Date()) {
        code = error.code
        stage = error.stage
        message = error.message
        diagnostics = error.diagnostics
        self.occurredAt = occurredAt
    }

    public var connectionError: ConnectionError {
        ConnectionError(code, stage: stage, message: message, diagnostics: diagnostics)
    }
}
