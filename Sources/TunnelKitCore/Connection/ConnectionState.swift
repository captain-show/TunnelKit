//
//  ConnectionState.swift
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

/// A fine-grained state of a VPN connection attempt.
///
/// Unlike `VPNStatus` (which mirrors what the OS reports), `ConnectionState`
/// tracks the *internal* lifecycle of a connection attempt, including the
/// mandatory `validating` stage that must succeed before `connected` may
/// be reported.
public enum ConnectionState: String, Codable, Sendable, CaseIterable {

    /// No connection attempt is in progress or has been made.
    case idle

    /// Configuration is being parsed and resources allocated.
    case preparing

    /// The transport socket is being established (incl. DNS resolution of the remote).
    case connecting

    /// The protocol handshake/negotiation is in progress.
    case negotiating

    /// The tunnel is formally up and is being validated for real-world usability.
    case validating

    /// The tunnel is up and validated.
    case connected

    /// An orderly shutdown is in progress.
    case disconnecting

    /// The connection is fully torn down after an orderly shutdown or before any attempt.
    case disconnected

    /// The connection attempt failed, or an established connection was lost.
    case failed

    /// `true` while a connection attempt or an established connection exists.
    public var isActive: Bool {
        switch self {
        case .preparing, .connecting, .negotiating, .validating, .connected:
            return true

        case .idle, .disconnecting, .disconnected, .failed:
            return false
        }
    }

    /// `true` when no further transitions are expected without a new attempt.
    public var isFinal: Bool {
        switch self {
        case .idle, .disconnected, .failed:
            return true

        default:
            return false
        }
    }

    /// The set of states this state may legally transition to.
    ///
    /// Notable invariants:
    /// - `connected` is only reachable from `validating`. Skipping validation is
    ///   structurally impossible.
    /// - Terminal states may only restart via `preparing`/`connecting`.
    public var allowedNextStates: Set<ConnectionState> {
        switch self {
        case .idle:
            // a stop before any start must be absorbable, not rejected
            return [.preparing, .connecting, .disconnecting, .disconnected]

        case .preparing:
            return [.connecting, .disconnecting, .disconnected, .failed]

        case .connecting:
            return [.negotiating, .connecting, .disconnecting, .disconnected, .failed]

        case .negotiating:
            return [.validating, .connecting, .disconnecting, .disconnected, .failed]

        case .validating:
            return [.connected, .connecting, .disconnecting, .disconnected, .failed]

        case .connected:
            // .validating allows re-validation when the server pushes new
            // options over an established session
            return [.validating, .connecting, .disconnecting, .disconnected, .failed]

        case .disconnecting:
            return [.disconnected, .failed]

        case .disconnected:
            return [.preparing, .connecting, .idle]

        case .failed:
            return [.preparing, .connecting, .disconnected, .idle]
        }
    }

    /// Returns whether transitioning to `next` is legal.
    public func canTransition(to next: ConnectionState) -> Bool {
        allowedNextStates.contains(next)
    }
}
