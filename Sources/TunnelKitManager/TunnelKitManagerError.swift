//
//  TunnelKitManagerError.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 6/16/23.
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

/// Errors returned by Core library.
public enum TunnelKitManagerError: Error, Sendable {
    case keychain(_ error: KeychainError)

    /// A notification was queried for a payload key it does not carry.
    case missingNotificationPayload(key: String)

    /// The system did not finish disconnecting before a reconnect attempt timed out.
    case disconnectionTimedOut(lastStatus: VPNStatus)
}

extension TunnelKitManagerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .keychain(let error):
            return "Keychain operation failed: \(error)"
        case .missingNotificationPayload(let key):
            return "VPN notification is missing the '\(key)' payload."
        case .disconnectionTimedOut(let lastStatus):
            return "VPN did not disconnect before the reconnect timeout (last status: \(lastStatus.rawValue))."
        }
    }
}
