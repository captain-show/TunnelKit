//
//  NetworkExtensionVPN.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 6/15/18.
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
@preconcurrency import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

/// `VPN` based on the NetworkExtension framework.
public class NetworkExtensionVPN: VPN, @unchecked Sendable {

    /**
     Initializes a provider.
     */
    public init() {
        let nc = NotificationCenter.default
        nc.addObserver(self, selector: #selector(vpnDidUpdate(_:)), name: .NEVPNStatusDidChange, object: nil)
        nc.addObserver(self, selector: #selector(vpnDidReinstall(_:)), name: .NEVPNConfigurationChange, object: nil)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    // MARK: Public

    public func prepare() async {
        do {
            _ = try await NETunnelProviderManager.loadAllFromPreferences()
        } catch {
            log.error("Unable to load VPN preferences: \(error)")
        }
    }

    public func install(
        _ tunnelBundleIdentifier: String,
        configuration: sending NetworkExtensionConfiguration,
        extra: sending NetworkExtensionExtra?
    ) async throws {
        _ = try await installReturningManager(
            tunnelBundleIdentifier,
            configuration: configuration,
            extra: extra
        )
    }

    public func reconnect(after: DispatchTimeInterval) async throws {
        let managers = try await lookupAll()
        guard let manager = managers.first else {
            return
        }
        if !manager.connection.status.isStopped {
            manager.connection.stopVPNTunnel()
            try await Task.sleep(for: after.duration)
            try await waitForDisconnection(of: manager)
        }
        try manager.connection.startVPNTunnel()
    }

    public func reconnect(
        _ tunnelBundleIdentifier: String,
        configuration: sending NetworkExtensionConfiguration,
        extra: sending NetworkExtensionExtra?,
        after: DispatchTimeInterval
    ) async throws {
        do {
            let manager = try await installReturningManager(
                tunnelBundleIdentifier,
                configuration: configuration,
                extra: extra
            )
            if !manager.connection.status.isStopped {
                manager.connection.stopVPNTunnel()
                try await Task.sleep(for: after.duration)
                try await waitForDisconnection(of: manager)
            }
            try manager.connection.startVPNTunnel()
        } catch {
            notifyInstallError(error)
            throw error
        }
    }

    public func disconnect() async {
        let managers: [NETunnelProviderManager]
        do {
            managers = try await lookupAll()
        } catch {
            log.error("Unable to load VPN preferences before disconnecting: \(error)")
            return
        }
        guard !managers.isEmpty else {
            return
        }
        for m in managers {
            // commit on-demand removal BEFORE stopping, or the system's
            // on-demand engine may immediately restart the tunnel
            m.isOnDemandEnabled = false
            m.isEnabled = false
            do {
                try await m.saveToPreferences()
            } catch {
                log.error("Unable to disable on-demand before disconnecting: \(error)")
            }
            m.connection.stopVPNTunnel()
        }
    }

    public func uninstall() async {
        let managers: [NETunnelProviderManager]
        do {
            managers = try await lookupAll()
        } catch {
            log.error("Unable to load VPN preferences before uninstalling: \(error)")
            return
        }
        guard !managers.isEmpty else {
            return
        }
        for m in managers {
            m.isOnDemandEnabled = false
            m.isEnabled = false
            do {
                try await m.saveToPreferences()
            } catch {
                log.error("Unable to disable VPN profile before uninstalling: \(error)")
            }
            m.connection.stopVPNTunnel()
            do {
                try await m.removeFromPreferences()
            } catch {
                log.error("Unable to remove VPN profile: \(error)")
            }
        }
    }

    /**
     Returns the current status of the tunnel with the given bundle identifier,
     or nil if no such tunnel is installed. Useful to seed UI state on cold
     launch instead of waiting for the next status transition.

     - Parameter tunnelBundleIdentifier: The bundle identifier of the tunnel extension.
     */
    public func currentStatus(ofTunnelBundleIdentifier tunnelBundleIdentifier: String) async throws -> (status: VPNStatus, connectionDate: Date?)? {
        let managers = try await lookupAll()
        guard let manager = managers.first(where: { $0.isTunnel(withIdentifier: tunnelBundleIdentifier) }) else {
            return nil
        }
        return (manager.connection.status.wrappedStatus, manager.connection.connectedDate)
    }

    /// Waits for the system tunnel to stop before a reconnect can begin.
    private func waitForDisconnection(
        of manager: NETunnelProviderManager,
        timeout: Duration = .seconds(5)
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)

        while !manager.connection.status.isStopped {
            try Task.checkCancellation()
            guard clock.now < deadline else {
                throw TunnelKitManagerError.disconnectionTimedOut(
                    lastStatus: manager.connection.status.wrappedStatus
                )
            }
            try await Task.sleep(for: .milliseconds(200))
        }
    }

    // MARK: Helpers

    @discardableResult
    private func installReturningManager(
        _ tunnelBundleIdentifier: String,
        configuration: NetworkExtensionConfiguration,
        extra: NetworkExtensionExtra?
    ) async throws -> NETunnelProviderManager {
        let proto = try configuration.asTunnelProtocol(
            withBundleIdentifier: tunnelBundleIdentifier,
            extra: extra
        )
        let managers = try await lookupAll()

        extra?.userData?.forEach {
            proto.providerConfiguration?[$0.key] = $0.value
        }

        // install (new or existing) then callback
        let targetManager = managers.first {
            $0.isTunnel(withIdentifier: tunnelBundleIdentifier)
        } ?? NETunnelProviderManager()

        _ = try await install(
            targetManager,
            title: configuration.title,
            protocolConfiguration: proto,
            onDemandRules: extra?.onDemandRules ?? []
        )

        // remove others afterwards (to avoid permission request)
        await retainManagers(managers) {
            $0.isTunnel(withIdentifier: tunnelBundleIdentifier)
        }

        return targetManager
    }

    @discardableResult
    private func install(
        _ manager: NETunnelProviderManager,
        title: String,
        protocolConfiguration: NETunnelProviderProtocol,
        onDemandRules: [NEOnDemandRule]
    ) async throws -> NETunnelProviderManager {
        manager.localizedDescription = title
        manager.protocolConfiguration = protocolConfiguration

        if !onDemandRules.isEmpty {
            manager.onDemandRules = onDemandRules
            manager.isOnDemandEnabled = true
        } else {
            manager.isOnDemandEnabled = false
        }

        manager.isEnabled = true
        do {
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            notifyReinstall(manager)
            return manager
        } catch {
            manager.isOnDemandEnabled = false
            manager.isEnabled = false
            notifyInstallError(error)
            throw error
        }
    }

    private func retainManagers(_ managers: [NETunnelProviderManager], isIncluded: (NETunnelProviderManager) -> Bool) async {
        let others = managers.filter {
            !isIncluded($0)
        }
        guard !others.isEmpty else {
            return
        }
        for o in others {
            do {
                try await o.removeFromPreferences()
            } catch {
                log.error("Unable to remove obsolete VPN profile: \(error)")
            }
        }
    }

    private func lookupAll() async throws -> [NETunnelProviderManager] {
        try await NETunnelProviderManager.loadAllFromPreferences()
    }

    // MARK: Notifications

    @objc private func vpnDidUpdate(_ notification: Notification) {
        guard let connection = notification.object as? NETunnelProviderSession else {
            return
        }
        notifyStatus(connection)
    }

    @objc private func vpnDidReinstall(_ notification: Notification) {
        guard let manager = notification.object as? NETunnelProviderManager else {
            return
        }
        notifyReinstall(manager)
    }

    private func notifyReinstall(_ manager: NETunnelProviderManager) {
        guard let bundleId = manager.tunnelBundleIdentifier else {
            return
        }
        log.debug("VPN did reinstall (\(bundleId)): isEnabled=\(manager.isEnabled)")

        var notification = Notification(name: VPNNotification.didReinstall)
        notification.vpnBundleIdentifier = bundleId
        notification.vpnIsEnabled = manager.isEnabled
        NotificationCenter.default.post(notification)
    }

    private func notifyStatus(_ connection: NETunnelProviderSession) {
        guard let _ = connection.manager.localizedDescription else {
            log.verbose("Ignoring VPN notification from bogus manager")
            return
        }
        guard let bundleId = connection.manager.tunnelBundleIdentifier else {
            return
        }
        let isEnabled = connection.manager.isEnabled
        let status = connection.status
        let connectionDate = connection.connectedDate
        log.debug("VPN status did change (\(bundleId)): isEnabled=\(isEnabled), status=\(status.rawValue)")

        guard status == .disconnected || status == .invalid else {
            Self.postStatusNotification(
                bundleIdentifier: bundleId,
                isEnabled: isEnabled,
                status: status.wrappedStatus,
                connectionDate: connectionDate,
                error: nil
            )
            return
        }

        // `fetchLastDisconnectError` is an async XPC round-trip. Only surface the
        // disconnect (and its reason) if the connection is STILL down when it
        // returns. During a stop→start reconnect (app reconnect, on-demand
        // restart), the live status advances to `.connecting`/`.connected`
        // synchronously while this fetch is in flight; posting a late
        // `.disconnected` then would contradict the current state and drive
        // consumers into a disconnect→reconnect loop. A genuine disconnect keeps
        // the status equal to the snapshot, so its reason is still delivered.
        connection.fetchLastDisconnectError { error in
            guard connection.status == status else {
                log.debug("Ignoring stale disconnect-error callback after status changed to \(connection.status.rawValue)")
                return
            }
            Self.postStatusNotification(
                bundleIdentifier: bundleId,
                isEnabled: isEnabled,
                status: status.wrappedStatus,
                connectionDate: connectionDate,
                error: error
            )
        }
    }

    private static func postStatusNotification(
        bundleIdentifier: String,
        isEnabled: Bool,
        status: VPNStatus,
        connectionDate: Date?,
        error: Error?
    ) {
        var notification = Notification(name: VPNNotification.didChangeStatus)
        notification.vpnBundleIdentifier = bundleIdentifier
        notification.vpnIsEnabled = isEnabled
        notification.vpnStatus = status
        notification.connectionDate = connectionDate
        notification.vpnErrorIfPresent = error
        NotificationCenter.default.post(notification)
    }

    private func notifyInstallError(_ error: Error) {
        log.error("VPN installation failed: \(error)")

        var notification = Notification(name: VPNNotification.didFail)
        notification.vpnError = error
        notification.vpnIsEnabled = false
        NotificationCenter.default.post(notification)
    }
}

private extension NEVPNManager {
    var tunnelBundleIdentifier: String? {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol else {
            log.warning("No bundle identifier found because protocolConfiguration is not NETunnelProviderProtocol (\(type(of: protocolConfiguration))")
            return nil
        }
        return proto.providerBundleIdentifier
    }

    func isTunnel(withIdentifier bundleIdentifier: String) -> Bool {
        return tunnelBundleIdentifier == bundleIdentifier
    }
}

private extension NEVPNStatus {
    var isStopped: Bool {
        self == .disconnected || self == .invalid
    }

    var wrappedStatus: VPNStatus {
        switch self {
        case .connected:
            return .connected

        case .connecting, .reasserting:
            return .connecting

        case .disconnecting:
            return .disconnecting

        case .disconnected, .invalid:
            return .disconnected

        @unknown default:
            return .disconnected
        }
    }
}
