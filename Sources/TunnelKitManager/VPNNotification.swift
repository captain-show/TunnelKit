//
//  VPNNotification.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 6/12/18.
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

/// VPN notifications.
public struct VPNNotification {

    /// The VPN did reinstall.
    public static let didReinstall = Notification.Name("VPNDidReinstall")

    /// The VPN did change its status.
    public static let didChangeStatus = Notification.Name("VPNDidChangeStatus")

    /// The VPN triggered some error.
    public static let didFail = Notification.Name("VPNDidFail")
}

extension Notification {

    /// The VPN bundle identifier, if the notification carries one.
    public var vpnBundleIdentifier: String? {
        get {
            userInfo?["BundleIdentifier"] as? String
        }
        set {
            var newInfo = userInfo ?? [:]
            newInfo["BundleIdentifier"] = newValue
            userInfo = newInfo
        }
    }

    /// The current VPN enabled state, if the notification carries one.
    public var vpnIsEnabledIfPresent: Bool? {
        get {
            userInfo?["IsEnabled"] as? Bool
        }
        set {
            setVPNPayload(newValue, forKey: "IsEnabled")
        }
    }

    /// The current VPN enabled state (false when the notification carries none).
    public var vpnIsEnabled: Bool {
        get {
            vpnIsEnabledIfPresent ?? false
        }
        set {
            vpnIsEnabledIfPresent = newValue
        }
    }

    /// The current VPN status, if the notification carries one.
    public var vpnStatusIfPresent: VPNStatus? {
        get {
            userInfo?["Status"] as? VPNStatus
        }
        set {
            setVPNPayload(newValue, forKey: "Status")
        }
    }

    /// The current VPN status (`.disconnected` when the notification carries none).
    public var vpnStatus: VPNStatus {
        get {
            vpnStatusIfPresent ?? .disconnected
        }
        set {
            vpnStatusIfPresent = newValue
        }
    }

    /// The triggered VPN error, if the notification carries one.
    public var vpnErrorIfPresent: Error? {
        get {
            userInfo?["Error"] as? Error
        }
        set {
            setVPNPayload(newValue, forKey: "Error")
        }
    }

    /// The triggered VPN error.
    public var vpnError: Error {
        get {
            vpnErrorIfPresent ?? TunnelKitManagerError.missingNotificationPayload(key: "Error")
        }
        set {
            vpnErrorIfPresent = newValue
        }
    }

    /// The current VPN connection date, if the notification carries one.
    public var connectionDate: Date? {
        get {
            userInfo?["ConnectionDate"] as? Date
        }
        set {
            var newInfo = userInfo ?? [:]
            newInfo["ConnectionDate"] = newValue
            userInfo = newInfo
        }
    }

    private mutating func setVPNPayload(_ value: Any?, forKey key: String) {
        var newInfo = userInfo ?? [:]
        newInfo[key] = value
        userInfo = newInfo
    }
}
