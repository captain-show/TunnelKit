import TunnelKitCore
import TunnelKitWireGuardCore
import TunnelKitWireGuardManager
// WireGuardKit has not adopted Swift concurrency annotations yet. The adapter
// serializes its mutable state on its own work queue.
@preconcurrency import WireGuardKit
import __TunnelKitUtils
import SwiftyBeaver

// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Darwin
import Foundation
import Network
import NetworkExtension
import os

/// NetworkExtension owns this NSObject subclass and does not offer an
/// actor-isolated subclass contract. Mutable provider state is confined to
/// `tunnelQueue`; completion registries use dedicated locks because start/stop
/// entry points may arrive on different queues.
open class WireGuardTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private final class StartCompletionBox: @unchecked Sendable {
        private let completion: (Error?) -> Void

        init(_ completion: @escaping (Error?) -> Void) {
            self.completion = completion
        }

        func callAsFunction(_ error: Error?) {
            completion(error)
        }
    }

    private final class StopCompletionBox: @unchecked Sendable {
        private let completion: () -> Void

        init(_ completion: @escaping () -> Void) {
            self.completion = completion
        }

        func callAsFunction() {
            completion()
        }
    }

    private final class AppMessageCompletionBox: @unchecked Sendable {
        private let completion: (Data?) -> Void

        init(_ completion: @escaping (Data?) -> Void) {
            self.completion = completion
        }

        func callAsFunction(_ response: Data?) {
            completion(response)
        }
    }

    private final class AttemptContext: @unchecked Sendable {
        let attempt: ConnectionAttemptToken
        let startedAt: Date
        let configuration: WireGuard.ProviderConfiguration
        let validationOptions: ConnectionValidationOptions
        let peerPublicKeys: Set<String>
        let validationDeadline: Date
        var monitoringFailureSince: Date?

        init(
            attempt: ConnectionAttemptToken,
            startedAt: Date,
            configuration: WireGuard.ProviderConfiguration,
            validationOptions: ConnectionValidationOptions,
            peerPublicKeys: Set<String>
        ) {
            self.attempt = attempt
            self.startedAt = startedAt
            self.configuration = configuration
            self.validationOptions = validationOptions
            self.peerPublicKeys = peerPublicKeys
            validationDeadline = startedAt.addingTimeInterval(max(0, validationOptions.maxDuration))
        }
    }

    private let pendingStarts = OSAllocatedUnfairLock<[ConnectionAttemptToken: StartCompletionBox]>(initialState: [:])
    private let pendingStops = OSAllocatedUnfairLock<[StopCompletionBox]>(initialState: [])

    /// The number of milliseconds between data count updates. Set to 0 to
    /// disable updates (default).
    public var dataCountInterval = 0

    /// Seconds between runtime polls while waiting for the first handshake.
    public var handshakePollInterval: TimeInterval = 0.5

    /// Keepalive installed on validation peers when their saved value is
    /// absent or less frequent. This actively starts otherwise idle profiles.
    public var validationKeepaliveInterval: UInt16 = 5

    /// Maximum acceptable age of a selected peer's handshake while connected.
    /// WireGuard normally rekeys after roughly two minutes, so this must not be
    /// reduced to a conventional HTTP-style heartbeat interval.
    public var handshakeFreshnessInterval: TimeInterval = 180

    /// Seconds between established-connection checks.
    public var connectivityWatchdogInterval: TimeInterval = 15

    /// Grace period for transient runtime/probe failures before the provider
    /// enters `reasserting` while WireGuard recovers in place.
    public var connectivityFailureGracePeriod: TimeInterval = 15

    private var activeContext: AttemptContext?
    private var tunnelIsStarted = false
    private var loggingDestinations: [BaseDestination] = []

    private let stateMachine = ConnectionStateMachine()
    private let tunnelQueue = DispatchQueue(label: WireGuardTunnelProvider.description(), qos: .utility)

    private lazy var adapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
    }()

    open override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let attempt = stateMachine.startNewAttempt(initialState: .preparing)
        let completionBox = StartCompletionBox(completionHandler)
        let supersededHandlers = pendingStarts.withLock { pendingStarts in
            let handlers = Array(pendingStarts.values)
            pendingStarts.removeAll()
            pendingStarts[attempt] = completionBox
            return handlers
        }
        let cancellation = connectionError(
            .cancelled,
            stage: .disconnection,
            message: "The WireGuard start was superseded by a newer attempt."
        )
        supersededHandlers.forEach { $0(cancellation) }

        tunnelQueue.async { [weak self] in
            self?.beginStart(attempt: attempt)
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wg_log(.info, staticMessage: "Stage: stopping tunnel")
        let completionBox = StopCompletionBox(completionHandler)
        pendingStops.withLock { $0.append(completionBox) }

        let invalidatedAttempt = stateMachine.beginAttempt()
        stateMachine.transition(to: .disconnecting)
        completeAllStarts(with: connectionError(
            .cancelled,
            stage: .disconnection,
            message: "The WireGuard start was cancelled while the tunnel was stopping."
        ))

        tunnelQueue.async { [weak self] in
            guard let self else {
                return
            }
            self.reasserting = false
            self.tunnelIsStarted = false
            self.activeContext = nil
            self.adapter.stop { [weak self] adapterError in
                guard let self else {
                    return
                }
                self.tunnelQueue.async {
                    if let adapterError, case .invalidState = adapterError {
                        wg_log(.debug, staticMessage: "WireGuard adapter was already stopped")
                    } else if let adapterError {
                        wg_log(.error, message: "Failed to stop WireGuard adapter: \(adapterError.localizedDescription)")
                    }
                    self.stateMachine.transition(to: .disconnected, attempt: invalidatedAttempt)
                    self.completeAllStops()

                    #if os(macOS)
                    // Work around Apple bug 32073323 until affected macOS
                    // versions are no longer supported.
                    exit(0)
                    #endif
                }
            }
        }
    }

    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else {
            return
        }
        guard messageData.count == 1, messageData[0] == 0 else {
            completionHandler(nil)
            return
        }
        // Touch `adapter` only on tunnelQueue: it is a lazy var and every other
        // access is serialized there, so first-initializing it from the NE
        // delivery thread here would race the start path's lazy initialization.
        let completionBox = AppMessageCompletionBox(completionHandler)
        tunnelQueue.async { [weak self] in
            guard let self else {
                completionBox(nil)
                return
            }
            self.adapter.getRuntimeConfiguration { settings in
                completionBox(settings?.data(using: .utf8))
            }
        }
    }

    // MARK: - Start lifecycle

    private func beginStart(attempt: ConnectionAttemptToken) {
        guard stateMachine.isCurrent(attempt) else {
            completeStart(attempt: attempt, with: connectionError(
                .cancelled,
                stage: .preparing,
                message: "The WireGuard start was superseded before configuration was loaded."
            ))
            return
        }

        reasserting = false

        guard let tunnelProviderProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let providerDictionary = tunnelProviderProtocol.providerConfiguration else {
            let error = connectionError(
                .invalidConfiguration,
                stage: .preparing,
                message: "The saved protocol configuration is missing or has an unexpected type."
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            completeStart(attempt: attempt, with: error)
            return
        }

        let configuration: WireGuard.ProviderConfiguration
        do {
            configuration = try fromDictionary(WireGuard.ProviderConfiguration.self, providerDictionary)
        } catch {
            let detailedError = connectionError(
                .invalidConfiguration,
                stage: .preparing,
                message: "The saved WireGuard provider configuration could not be decoded.",
                underlying: error
            )
            stateMachine.transition(to: .failed, attempt: attempt)
            completeStart(attempt: attempt, with: detailedError)
            return
        }

        configureLogging(configuration: configuration)
        configuration._appexSetLastError(nil)
        configuration._appexSetDataCount(nil)

        // Validation is opt-in: an unset policy must NOT fail a healthy tunnel.
        // End-to-end WireGuard probes also require iOS 18/macOS 15, so defaulting
        // to enabled would additionally hard-fail every start on iOS 17/macOS 14.
        // Apps opt into `.default`/`.strict` explicitly when they want it.
        let validationOptions = configuration.connectionValidation ?? .disabled
        let invalidValidationFields = Self.invalidValidationFields(in: validationOptions)
        if validationOptions.isEnabled, !invalidValidationFields.isEmpty {
            let error = connectionError(
                .invalidConfiguration,
                stage: .validation,
                message: "WireGuard connectivity validation options are invalid.",
                diagnostics: ["invalidFields": invalidValidationFields.joined(separator: ",")]
            )
            configuration._appexSetLastError(.connectionValidationFailed, connectionError: error)
            stateMachine.transition(to: .failed, attempt: attempt)
            completeStart(attempt: attempt, with: error)
            return
        }
        if validationOptions.isEnabled,
           validationOptions.probes.contains(where: { probe in
               if case .gatewayPing = probe {
                   return true
               }
               return false
           }) {
            let error = connectionError(
                .unsupportedConfiguration,
                stage: .validation,
                message: "WireGuard has no tunnel gateway that can satisfy a gatewayPing probe. Configure an external DNS or numeric ping target instead."
            )
            configuration._appexSetLastError(.connectionValidationFailed, connectionError: error)
            stateMachine.transition(to: .failed, attempt: attempt)
            completeStart(attempt: attempt, with: error)
            return
        }
        if validationOptions.isEnabled, !Self.supportsVirtualInterfaceProbes {
            let error = connectionError(
                .unsupportedConfiguration,
                stage: .validation,
                message: "End-to-end WireGuard validation requires iOS 18, macOS 15, or newer. Disable validation explicitly to opt into handshake-only legacy behavior."
            )
            configuration._appexSetLastError(.connectionValidationFailed, connectionError: error)
            stateMachine.transition(to: .failed, attempt: attempt)
            completeStart(attempt: attempt, with: error)
            return
        }
        let peerPublicKeys = configuration.configuration.validationPeerPublicKeys(for: validationOptions.probes)
        if validationOptions.isEnabled, peerPublicKeys.isEmpty {
            let error = connectionError(
                .invalidConfiguration,
                stage: .validation,
                message: "No WireGuard peer routes any configured connectivity probe.",
                diagnostics: ["probes": "\(validationOptions.probes.count)"]
            )
            configuration._appexSetLastError(.connectionValidationFailed, connectionError: error)
            stateMachine.transition(to: .failed, attempt: attempt)
            completeStart(attempt: attempt, with: error)
            return
        }

        let context = AttemptContext(
            attempt: attempt,
            startedAt: Date(),
            configuration: configuration,
            validationOptions: validationOptions,
            peerPublicKeys: peerPublicKeys
        )
        activeContext = context

        let tunnelConfiguration: TunnelConfiguration
        if validationOptions.isEnabled {
            tunnelConfiguration = configuration.configuration.tunnelConfigurationActivatingKeepalive(
                for: peerPublicKeys,
                interval: validationKeepaliveInterval
            )
        } else {
            tunnelConfiguration = configuration.configuration.tunnelConfiguration
        }

        wg_log(.info, staticMessage: "Stage: starting WireGuard backend")
        stateMachine.transition(to: .connecting, attempt: attempt)
        adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
            guard let self else {
                return
            }
            self.tunnelQueue.async {
                self.didStartAdapter(adapterError, context: context)
            }
        }
    }

    private func didStartAdapter(_ adapterError: WireGuardAdapterError?, context: AttemptContext) {
        guard isActive(context, expectedState: .connecting) else {
            completeStart(attempt: context.attempt, with: connectionError(
                .cancelled,
                stage: .protocolHandshake,
                message: "The WireGuard backend result belongs to a superseded attempt."
            ))
            return
        }

        if let adapterError {
            let (legacyError, detailedError) = unifiedError(from: adapterError)
            context.configuration._appexSetLastError(legacyError, connectionError: detailedError)
            stateMachine.transition(to: .failed, attempt: context.attempt)
            activeContext = nil
            completeStart(attempt: context.attempt, with: detailedError)
            return
        }

        wg_log(.info, message: "Tunnel interface is \(adapter.interfaceName ?? "unknown")")
        guard stateMachine.transition(to: .negotiating, attempt: context.attempt).isAccepted else {
            completeStart(attempt: context.attempt, with: connectionError(
                .cancelled,
                stage: .protocolHandshake,
                message: "The WireGuard start was superseded after the backend started."
            ))
            return
        }

        guard context.validationOptions.isEnabled else {
            wg_log(.default, staticMessage: "Stage: connectivity validation explicitly disabled")
            enterValidatingAndDeclareConnected(context: context)
            return
        }

        wg_log(.info, staticMessage: "Stage: waiting for a fresh selected-peer handshake")
        let handshakeDeadline = min(
            context.validationDeadline,
            context.startedAt.addingTimeInterval(max(0, context.validationOptions.handshakeTimeout))
        )
        awaitInitialHandshake(context: context, deadline: handshakeDeadline)
    }

    private func awaitInitialHandshake(context: AttemptContext, deadline: Date) {
        guard isActive(context, expectedState: .negotiating) else {
            completeStart(attempt: context.attempt, with: connectionError(
                .cancelled,
                stage: .protocolHandshake,
                message: "The WireGuard handshake wait was cancelled."
            ))
            return
        }

        adapter.getRuntimeConfiguration { [weak self] settings in
            guard let self else {
                return
            }
            self.tunnelQueue.async {
                guard self.isActive(context, expectedState: .negotiating) else {
                    self.completeStart(attempt: context.attempt, with: connectionError(
                        .cancelled,
                        stage: .protocolHandshake,
                        message: "The WireGuard handshake result belongs to a superseded attempt."
                    ))
                    return
                }

                let runtimeInfo = settings.flatMap(WireGuardRuntimeInfo.from(wireGuardString:))
                if runtimeInfo?.hasFreshHandshake(
                    peerPublicKeys: context.peerPublicKeys,
                    policy: context.validationOptions.policy,
                    now: Date(),
                    maximumAge: self.handshakeFreshnessInterval,
                    notBefore: context.startedAt
                ) == true {
                    wg_log(.info, staticMessage: "Stage: selected-peer handshake confirmed")
                    self.beginConnectivityValidation(context: context)
                    return
                }

                guard Date() < deadline else {
                    let error = connectionError(
                        .handshakeTimeout,
                        stage: .protocolHandshake,
                        message: "No selected WireGuard peer completed a fresh handshake before the deadline.",
                        diagnostics: [
                            "peerCount": "\(context.peerPublicKeys.count)",
                            "timeout": "\(context.validationOptions.handshakeTimeout)"
                        ]
                    )
                    self.failStart(
                        legacyError: .handshakeTimeout,
                        connectionError: error,
                        context: context
                    )
                    return
                }

                self.tunnelQueue.asyncAfter(deadline: .now() + max(0.05, self.handshakePollInterval)) {
                    self.awaitInitialHandshake(context: context, deadline: deadline)
                }
            }
        }
    }

    private func beginConnectivityValidation(context: AttemptContext) {
        guard stateMachine.transition(to: .validating, attempt: context.attempt).isAccepted else {
            completeStart(attempt: context.attempt, with: connectionError(
                .cancelled,
                stage: .validation,
                message: "Connectivity validation was superseded."
            ))
            return
        }

        validateActiveProbes(context: context, deadline: context.validationDeadline) { [weak self] result in
            guard let self, self.isActive(context, expectedState: .validating) else {
                return
            }
            switch result {
            case .success:
                self.stabilize(context: context)
            case .failure(let error):
                self.failStart(
                    legacyError: .connectionValidationFailed,
                    connectionError: error,
                    context: context
                )
            }
        }
    }

    private func stabilize(context: AttemptContext) {
        let period = max(0, context.validationOptions.stabilizationPeriod)
        guard period > 0 else {
            declareConnected(context: context)
            return
        }
        guard Date().addingTimeInterval(period) <= context.validationDeadline else {
            failStart(
                legacyError: .connectionValidationFailed,
                connectionError: connectionError(
                    .validationFailed,
                    stage: .validation,
                    message: "The validation deadline is too short for the configured stabilization period."
                ),
                context: context
            )
            return
        }

        wg_log(.info, message: "Stage: stabilizing for \(period)s")
        tunnelQueue.asyncAfter(deadline: .now() + period) { [weak self] in
            self?.revalidateAfterStabilization(context: context)
        }
    }

    private func revalidateAfterStabilization(context: AttemptContext) {
        guard isActive(context, expectedState: .validating) else {
            completeStart(attempt: context.attempt, with: connectionError(
                .cancelled,
                stage: .validation,
                message: "WireGuard stabilization was cancelled."
            ))
            return
        }

        adapter.getRuntimeConfiguration { [weak self] settings in
            guard let self else {
                return
            }
            self.tunnelQueue.async {
                guard self.isActive(context, expectedState: .validating) else {
                    return
                }
                let runtimeInfo = settings.flatMap(WireGuardRuntimeInfo.from(wireGuardString:))
                guard runtimeInfo?.hasFreshHandshake(
                    peerPublicKeys: context.peerPublicKeys,
                    policy: context.validationOptions.policy,
                    now: Date(),
                    maximumAge: self.handshakeFreshnessInterval,
                    notBefore: context.startedAt
                ) == true else {
                    self.failStart(
                        legacyError: .connectionValidationFailed,
                        connectionError: connectionError(
                            .validationFailed,
                            stage: .validation,
                            message: "The selected WireGuard peer lost handshake evidence during stabilization."
                        ),
                        context: context
                    )
                    return
                }

                self.validateActiveProbes(
                    context: context,
                    deadline: context.validationDeadline
                ) { result in
                    guard self.isActive(context, expectedState: .validating) else {
                        return
                    }
                    switch result {
                    case .success:
                        self.declareConnected(context: context)
                    case .failure(let error):
                        self.failStart(
                            legacyError: .connectionValidationFailed,
                            connectionError: error,
                            context: context
                        )
                    }
                }
            }
        }
    }

    private func enterValidatingAndDeclareConnected(context: AttemptContext) {
        guard stateMachine.transition(to: .validating, attempt: context.attempt).isAccepted else {
            completeStart(attempt: context.attempt, with: connectionError(
                .cancelled,
                stage: .validation,
                message: "The disabled-validation start was superseded."
            ))
            return
        }
        declareConnected(context: context)
    }

    private func declareConnected(context: AttemptContext) {
        guard isActive(context, expectedState: .validating),
              stateMachine.transition(to: .connected, attempt: context.attempt).isAccepted else {
            completeStart(attempt: context.attempt, with: connectionError(
                .cancelled,
                stage: .validation,
                message: "The WireGuard connection was superseded before it became usable."
            ))
            return
        }
        wg_log(.info, staticMessage: "Stage: connected and validated")
        reasserting = false
        tunnelIsStarted = true
        refreshDataCount(context: context)
        scheduleConnectivityWatchdog(context: context)
        completeStart(attempt: context.attempt, with: nil)
    }

    private func failStart(
        legacyError: TunnelKitWireGuardError,
        connectionError detailedError: ConnectionError,
        context: AttemptContext
    ) {
        guard stateMachine.isCurrent(context.attempt) else {
            completeStart(attempt: context.attempt, with: detailedError)
            return
        }
        context.configuration._appexSetLastError(legacyError, connectionError: detailedError)
        stateMachine.transition(to: .failed, attempt: context.attempt)
        tunnelIsStarted = false
        activeContext = nil
        adapter.stop { [weak self] stopError in
            if let stopError, case .invalidState = stopError {
                wg_log(.debug, staticMessage: "WireGuard adapter was already stopped after failed start")
            } else if let stopError {
                wg_log(.error, message: "Failed to stop WireGuard adapter after failed start: \(stopError.localizedDescription)")
            }
            guard let self else {
                return
            }
            self.tunnelQueue.async {
                self.completeStart(attempt: context.attempt, with: detailedError)
            }
        }
    }

    // MARK: - Active validation

    private func validateActiveProbes(
        context: AttemptContext,
        deadline: Date,
        completion: @escaping (Result<Void, ConnectionError>) -> Void
    ) {
        let explicitProbes = context.validationOptions.probes.filter { probe in
            if case .gatewayPing = probe {
                return false
            }
            return true
        }
        if explicitProbes.isEmpty {
            completion(.failure(connectionError(
                .validationFailed,
                stage: .validation,
                message: "A WireGuard handshake proves peer reachability but not end-to-end network access.",
                diagnostics: ["probes": "gatewayPing-only"]
            )))
            return
        }

        guard Date() < deadline else {
            completion(.failure(connectionError(
                .validationFailed,
                stage: .validation,
                message: "Connectivity validation exceeded its overall deadline."
            )))
            return
        }

        guard #available(iOS 18.0, macOS 15.0, tvOS 18.0, visionOS 2.0, *),
              let interface = virtualInterface else {
            completion(.failure(connectionError(
                .unsupportedConfiguration,
                stage: .validation,
                message: "End-to-end WireGuard probes require iOS 18, macOS 15, or newer.",
                diagnostics: ["probeCount": "\(explicitProbes.count)"]
            )))
            return
        }

        runActiveProbes(
            explicitProbes,
            index: 0,
            lastError: nil,
            interface: interface,
            context: context,
            deadline: deadline,
            completion: completion
        )
    }

    @available(iOS 18.0, macOS 15.0, tvOS 18.0, visionOS 2.0, *)
    private func runActiveProbes(
        _ probes: [ConnectionValidationOptions.Probe],
        index: Int,
        lastError: ConnectionError?,
        interface: NWInterface,
        context: AttemptContext,
        deadline: Date,
        completion: @escaping (Result<Void, ConnectionError>) -> Void
    ) {
        guard index < probes.count else {
            if context.validationOptions.policy == .all {
                completion(.success(()))
            } else {
                completion(.failure(lastError ?? connectionError(
                    .validationFailed,
                    stage: .validation,
                    message: "No configured end-to-end probe succeeded."
                )))
            }
            return
        }

        runActiveProbe(
            probes[index],
            attemptNumber: 1,
            interface: interface,
            context: context,
            deadline: deadline
        ) { [weak self] result in
            guard let self, self.stateMachine.isCurrent(context.attempt) else {
                return
            }
            switch result {
            case .success:
                if context.validationOptions.policy == .any {
                    completion(.success(()))
                } else {
                    self.runActiveProbes(
                        probes,
                        index: index + 1,
                        lastError: nil,
                        interface: interface,
                        context: context,
                        deadline: deadline,
                        completion: completion
                    )
                }
            case .failure(let error):
                if context.validationOptions.policy == .all {
                    completion(.failure(error))
                } else {
                    self.runActiveProbes(
                        probes,
                        index: index + 1,
                        lastError: error,
                        interface: interface,
                        context: context,
                        deadline: deadline,
                        completion: completion
                    )
                }
            }
        }
    }

    @available(iOS 18.0, macOS 15.0, tvOS 18.0, visionOS 2.0, *)
    private func runActiveProbe(
        _ probe: ConnectionValidationOptions.Probe,
        attemptNumber: Int,
        interface: NWInterface,
        context: AttemptContext,
        deadline: Date,
        completion: @escaping (Result<Void, ConnectionError>) -> Void
    ) {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else {
            completion(.failure(connectionError(
                .validationFailed,
                stage: .validation,
                message: "The end-to-end probe exceeded the overall validation deadline."
            )))
            return
        }
        let timeout = min(max(0.1, context.validationOptions.probeTimeout), remaining)

        let finishAttempt: (Result<Void, ConnectionError>) -> Void = { [weak self] result in
            guard let self else {
                return
            }
            if case .failure = result,
               attemptNumber < max(1, context.validationOptions.probeAttempts),
               Date() < deadline {
                self.runActiveProbe(
                    probe,
                    attemptNumber: attemptNumber + 1,
                    interface: interface,
                    context: context,
                    deadline: deadline,
                    completion: completion
                )
            } else {
                completion(result)
            }
        }

        switch probe {
        case .gatewayPing:
            finishAttempt(.success(()))

        case .ping(let host):
            ICMPProbe(
                host: host,
                interfaceName: interface.name,
                timeout: timeout,
                queue: tunnelQueue,
                completion: finishAttempt
            ).start()

        case .dns(let hostname, let configuredServer):
            guard let server = configuredServer ?? context.configuration.configuration.dnsServers.first else {
                finishAttempt(.failure(connectionError(
                    .invalidConfiguration,
                    stage: .validation,
                    message: "A DNS probe was configured without a DNS server."
                )))
                return
            }
            DNSProbe(
                hostname: hostname,
                server: server,
                interface: interface,
                timeout: timeout,
                queue: tunnelQueue,
                completion: finishAttempt
            ).start()
        }
    }

    // MARK: - Established monitoring

    private func scheduleConnectivityWatchdog(context: AttemptContext) {
        guard context.validationOptions.isEnabled,
              connectivityWatchdogInterval.isFinite,
              connectivityWatchdogInterval > 0 else {
            return
        }
        tunnelQueue.asyncAfter(deadline: .now() + connectivityWatchdogInterval) { [weak self] in
            self?.runConnectivityWatchdog(context: context)
        }
    }

    private func runConnectivityWatchdog(context: AttemptContext) {
        guard isActive(context, expectedState: .connected), tunnelIsStarted else {
            return
        }

        adapter.getRuntimeConfiguration { [weak self] settings in
            guard let self else {
                return
            }
            self.tunnelQueue.async {
                guard self.isActive(context, expectedState: .connected), self.tunnelIsStarted else {
                    return
                }
                let runtimeInfo = settings.flatMap(WireGuardRuntimeInfo.from(wireGuardString:))
                let hasFreshHandshake = runtimeInfo?.hasFreshHandshake(
                    peerPublicKeys: context.peerPublicKeys,
                    policy: context.validationOptions.policy,
                    now: Date(),
                    maximumAge: self.handshakeFreshnessInterval,
                    notBefore: context.startedAt
                ) == true

                guard hasFreshHandshake else {
                    self.recordMonitoringFailure(
                        context: context,
                        error: connectionError(
                            .connectionLost,
                            stage: .monitoring,
                            message: "The selected WireGuard peer no longer has a fresh handshake.",
                            diagnostics: ["maximumAge": "\(self.handshakeFreshnessInterval)"]
                        )
                    )
                    return
                }

                let monitoringDeadline = Date().addingTimeInterval(
                    max(0.1, context.validationOptions.maxDuration)
                )
                self.validateActiveProbes(
                    context: context,
                    deadline: monitoringDeadline
                ) { result in
                    guard self.isActive(context, expectedState: .connected) else {
                        return
                    }
                    switch result {
                    case .success:
                        context.monitoringFailureSince = nil
                        if self.reasserting {
                            wg_log(.info, staticMessage: "Stage: connectivity restored")
                        }
                        self.reasserting = false
                        context.configuration._appexSetLastError(nil)
                        self.scheduleConnectivityWatchdog(context: context)
                    case .failure(let error):
                        self.recordMonitoringFailure(context: context, error: error)
                    }
                }
            }
        }
    }

    private func recordMonitoringFailure(context: AttemptContext, error: ConnectionError) {
        let now = Date()
        if context.monitoringFailureSince == nil {
            context.monitoringFailureSince = now
        }
        let failureDuration = now.timeIntervalSince(context.monitoringFailureSince ?? now)
        let gracePeriod = connectivityFailureGracePeriod.isFinite
            ? max(0, connectivityFailureGracePeriod)
            : 0
        guard failureDuration >= gracePeriod else {
            wg_log(.info, message: "Stage: transient connectivity failure; rechecking within the \(gracePeriod)s grace period")
            scheduleConnectivityWatchdog(context: context)
            return
        }

        let detailedError = connectionError(
            .connectionLost,
            stage: .monitoring,
            message: error.message,
            underlying: error,
            diagnostics: error.diagnostics.merging([
                "failureDuration": "\(failureDuration)",
                "gracePeriod": "\(gracePeriod)"
            ]) { current, _ in current }
        )
        context.configuration._appexSetLastError(.connectionValidationFailed, connectionError: detailedError)
        if !reasserting {
            wg_log(.error, message: "Stage: connectivity lost; WireGuard is reasserting: \(detailedError)")
        } else {
            wg_log(.default, message: "Stage: connectivity is still unavailable: \(detailedError)")
        }
        // The WireGuard backend already performs its own roaming and handshake
        // recovery. Cancelling the provider here makes on-demand immediately
        // start it again, producing an endless disconnect/connect loop. Keep
        // the adapter alive, report the outage honestly, and poll until both
        // handshake and end-to-end validation recover.
        reasserting = true
        scheduleConnectivityWatchdog(context: context)
    }

    // MARK: - Data count

    private func refreshDataCount(context: AttemptContext) {
        guard dataCountInterval > 0 else {
            return
        }
        guard isActive(context, expectedState: .connected), tunnelIsStarted else {
            context.configuration._appexSetDataCount(nil)
            return
        }

        adapter.getRuntimeConfiguration { [weak self] configurationString in
            guard let self else {
                return
            }
            self.tunnelQueue.async {
                guard self.isActive(context, expectedState: .connected), self.tunnelIsStarted else {
                    return
                }
                if let configurationString,
                   let runtimeInfo = WireGuardRuntimeInfo.from(wireGuardString: configurationString) {
                    context.configuration._appexSetDataCount(runtimeInfo.dataCount)
                } else {
                    wg_log(.error, staticMessage: "Failed to parse WireGuard runtime counters")
                }
                self.tunnelQueue.asyncAfter(
                    deadline: .now() + .milliseconds(max(1, self.dataCountInterval))
                ) {
                    self.refreshDataCount(context: context)
                }
            }
        }
    }

    // MARK: - Completion and errors

    private func completeStart(attempt: ConnectionAttemptToken, with error: Error?) {
        let completion = pendingStarts.withLock { $0.removeValue(forKey: attempt) }
        completion?(error)
    }

    private func completeAllStarts(with error: Error) {
        let completions = pendingStarts.withLock { pendingStarts in
            let completions = Array(pendingStarts.values)
            pendingStarts.removeAll()
            return completions
        }
        completions.forEach { $0(error) }
    }

    private func completeAllStops() {
        let completions = pendingStops.withLock { pendingStops in
            let completions = pendingStops
            pendingStops.removeAll()
            return completions
        }
        completions.forEach { $0() }
    }

    private func isActive(_ context: AttemptContext, expectedState: ConnectionState) -> Bool {
        activeContext === context
            && stateMachine.isCurrent(context.attempt)
            && stateMachine.state == expectedState
    }

    private static var supportsVirtualInterfaceProbes: Bool {
        if #available(iOS 18.0, macOS 15.0, tvOS 18.0, visionOS 2.0, *) {
            return true
        }
        return false
    }

    private static func invalidValidationFields(
        in options: ConnectionValidationOptions
    ) -> [String] {
        var invalidFields: [String] = []
        if !options.probeTimeout.isFinite || options.probeTimeout <= 0 {
            invalidFields.append("probeTimeout")
        }
        if options.probeAttempts <= 0 {
            invalidFields.append("probeAttempts")
        }
        if !options.stabilizationPeriod.isFinite || options.stabilizationPeriod < 0 {
            invalidFields.append("stabilizationPeriod")
        }
        if !options.handshakeTimeout.isFinite || options.handshakeTimeout <= 0 {
            invalidFields.append("handshakeTimeout")
        }
        if !options.maxDuration.isFinite || options.maxDuration <= 0 {
            invalidFields.append("maxDuration")
        }
        if options.probes.isEmpty || options.probes.count > 32 {
            invalidFields.append("probes")
        }
        return invalidFields
    }

    private func unifiedError(from adapterError: WireGuardAdapterError) -> (TunnelKitWireGuardError, ConnectionError) {
        switch adapterError {
        case .cannotLocateTunnelFileDescriptor:
            return (.couldNotDetermineFileDescriptor, connectionError(
                .tunnelSetupFailed,
                stage: .applyingNetworkSettings,
                message: "The WireGuard adapter could not locate the tunnel file descriptor."
            ))

        case .dnsResolution(let dnsErrors):
            let addresses = dnsErrors.map(\.address)
            let resolutionErrors = dnsErrors.map { "\($0.address):\($0.errorCode)" }
            return (.dnsResolutionFailure, connectionError(
                .dnsFailure,
                stage: .dnsResolution,
                message: "One or more WireGuard peer endpoints could not be resolved.",
                diagnostics: [
                    "addresses": addresses.joined(separator: ", "),
                    "resolutionErrors": resolutionErrors.joined(separator: ", ")
                ]
            ))

        case .setNetworkSettings(let underlyingError):
            return (.couldNotSetNetworkSettings, connectionError(
                .tunnelSetupFailed,
                stage: .applyingNetworkSettings,
                message: "NetworkExtension rejected the WireGuard tunnel settings.",
                underlying: underlyingError
            ))

        case .startWireGuardBackend(let errorCode):
            return (.couldNotStartBackend, connectionError(
                .tunnelSetupFailed,
                stage: .protocolHandshake,
                message: "The WireGuard backend failed to start.",
                diagnostics: ["backendCode": "\(errorCode)"]
            ))

        case .invalidState:
            return (.couldNotStartBackend, connectionError(
                .internalError,
                stage: .preparing,
                message: "The WireGuard adapter rejected the operation in its current state."
            ))
//        case .setWireGuardConfiguration(let errorCode):
//            return (.couldNotStartBackend, connectionError(
//                .tunnelSetupFailed,
//                stage: .protocolHandshake,
//                message: "The WireGuard backend failed to apply its configuration.",
//                diagnostics: ["backendCode": "\(errorCode)"]
//            ))
        }
    }

    private func configureLogging(configuration: WireGuard.ProviderConfiguration) {
        loggingDestinations.forEach { SwiftyBeaver.removeDestination($0) }
        loggingDestinations.removeAll()

        let logLevel: SwiftyBeaver.Level = configuration.shouldDebug ? .debug : .info
        let logFormat = configuration.debugLogFormat ?? "$Dyyyy-MM-dd HH:mm:ss.SSS$d $L $N.$F:$l - $M"

        if configuration.shouldDebug {
            let console = ConsoleDestination()
            console.useNSLog = true
            console.minLevel = logLevel
            console.format = logFormat
            SwiftyBeaver.addDestination(console)
            loggingDestinations.append(console)
        }

        let file = FileDestination(logFileURL: configuration._appexDebugLogURL)
        file.minLevel = logLevel
        file.format = logFormat
        file.logFileMaxSize = 20_000
        SwiftyBeaver.addDestination(file)
        loggingDestinations.append(file)
        configuration._appexSetDebugLogPath()
    }
}

private func connectionError(
    _ code: ConnectionError.Code,
    stage: ConnectionStage,
    message: String,
    underlying: Error? = nil,
    diagnostics: [String: String] = [:]
) -> ConnectionError {
    ConnectionError(
        code,
        stage: stage,
        message: message,
        underlying: underlying,
        diagnostics: diagnostics
    )
}

@available(iOS 18.0, macOS 15.0, tvOS 18.0, visionOS 2.0, *)
private final class DNSProbe: @unchecked Sendable {
    private let transactionID = UInt16.random(in: .min ... .max)
    private let hostname: String
    private let server: String
    private let timeout: TimeInterval
    private let queue: DispatchQueue
    private let completion: (Result<Void, ConnectionError>) -> Void
    private let connection: NWConnection
    private var isCompleted = false
    private var timeoutWorkItem: DispatchWorkItem?

    init(
        hostname: String,
        server: String,
        interface: NWInterface,
        timeout: TimeInterval,
        queue: DispatchQueue,
        completion: @escaping (Result<Void, ConnectionError>) -> Void
    ) {
        self.hostname = hostname
        self.server = server
        self.timeout = timeout
        self.queue = queue
        self.completion = completion
        let parameters = NWParameters.udp
        parameters.requiredInterface = interface
        connection = NWConnection(host: NWEndpoint.Host(server), port: 53, using: parameters)
    }

    func start() {
        guard let query = Self.makeQuery(hostname: hostname, transactionID: transactionID) else {
            finish(.failure(connectionError(
                .invalidConfiguration,
                stage: .validation,
                message: "The DNS validation hostname is invalid.",
                diagnostics: ["probe": "dns"]
            )))
            return
        }

        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                self.connection.send(content: query, completion: .contentProcessed { [self] error in
                    if let error {
                        self.finish(.failure(self.probeError("DNS query send failed.", underlying: error)))
                        return
                    }
                    self.connection.receiveMessage { [self] data, _, _, error in
                        if let error {
                            self.finish(.failure(self.probeError("DNS response receive failed.", underlying: error)))
                        } else if let data, Self.isResponse(data, transactionID: self.transactionID) {
                            self.finish(.success(()))
                        } else {
                            self.finish(.failure(self.probeError("DNS server returned no matching response.")))
                        }
                    }
                })
            case .failed(let error):
                self.finish(.failure(self.probeError("DNS probe connection failed.", underlying: error)))
            case .cancelled:
                break
            default:
                break
            }
        }

        let timeoutWorkItem = DispatchWorkItem { [self] in
            self.finish(.failure(self.probeError("DNS probe timed out after \(self.timeout)s.")))
        }
        self.timeoutWorkItem = timeoutWorkItem
        queue.asyncAfter(deadline: .now() + timeout, execute: timeoutWorkItem)
        connection.start(queue: queue)
    }

    private func finish(_ result: Result<Void, ConnectionError>) {
        guard !isCompleted else {
            return
        }
        isCompleted = true
        timeoutWorkItem?.cancel()
        timeoutWorkItem = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        completion(result)
    }

    private func probeError(_ message: String, underlying: Error? = nil) -> ConnectionError {
        connectionError(
            .validationFailed,
            stage: .validation,
            message: message,
            underlying: underlying,
            diagnostics: ["probe": "dns", "server": server]
        )
    }

    private static func makeQuery(hostname: String, transactionID: UInt16) -> Data? {
        let labels = hostname.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty,
              labels.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 }),
              hostname.utf8.count <= 253 else {
            return nil
        }

        var query = Data([
            UInt8(transactionID >> 8), UInt8(truncatingIfNeeded: transactionID),
            0x01, 0x00, // recursion desired
            0x00, 0x01, // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ])
        for label in labels {
            query.append(UInt8(label.utf8.count))
            query.append(contentsOf: label.utf8)
        }
        query.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01]) // A / IN
        return query
    }

    private static func isResponse(_ data: Data, transactionID: UInt16) -> Bool {
        guard data.count >= 12 else {
            return false
        }
        let responseID = UInt16(data[data.startIndex]) << 8
            | UInt16(data[data.index(after: data.startIndex)])
        let highFlagsIndex = data.index(data.startIndex, offsetBy: 2)
        let lowFlagsIndex = data.index(data.startIndex, offsetBy: 3)
        let answerCountIndex = data.index(data.startIndex, offsetBy: 6)
        let answerCount = UInt16(data[answerCountIndex]) << 8
            | UInt16(data[data.index(after: answerCountIndex)])
        return responseID == transactionID
            && data[highFlagsIndex] & 0x80 != 0
            && data[lowFlagsIndex] & 0x0f == 0
            && answerCount > 0
    }
}

@available(iOS 18.0, macOS 15.0, tvOS 18.0, visionOS 2.0, *)
private final class ICMPProbe: @unchecked Sendable {
    private let host: String
    private let interfaceName: String
    private let timeout: TimeInterval
    private let queue: DispatchQueue
    private let completion: (Result<Void, ConnectionError>) -> Void
    private let identifier = UInt16.random(in: .min ... .max)
    private let sequence = UInt16.random(in: .min ... .max)
    private let nonce = UInt64.random(in: .min ... .max)
    private var descriptor: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var timeoutWorkItem: DispatchWorkItem?
    private var isCompleted = false
    private var echoReplyType: UInt8 = 0

    init(
        host: String,
        interfaceName: String,
        timeout: TimeInterval,
        queue: DispatchQueue,
        completion: @escaping (Result<Void, ConnectionError>) -> Void
    ) {
        self.host = host
        self.interfaceName = interfaceName
        self.timeout = timeout
        self.queue = queue
        self.completion = completion
    }

    func start() {
        var ipv4Destination = sockaddr_in()
        ipv4Destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        ipv4Destination.sin_family = sa_family_t(AF_INET)
        var ipv6Destination = sockaddr_in6()
        ipv6Destination.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        ipv6Destination.sin6_family = sa_family_t(AF_INET6)

        let addressFamily: Int32
        let protocolNumber: Int32
        let protocolLevel: Int32
        let boundInterfaceOption: Int32
        let echoRequestType: UInt8
        let connectSocket: () -> Int32
        if host.withCString({ inet_pton(AF_INET, $0, &ipv4Destination.sin_addr) }) == 1 {
            addressFamily = AF_INET
            protocolNumber = IPPROTO_ICMP
            protocolLevel = IPPROTO_IP
            boundInterfaceOption = IP_BOUND_IF
            echoRequestType = 8
            echoReplyType = 0
            connectSocket = { [self] in
                withUnsafePointer(to: &ipv4Destination) { destinationPointer in
                    destinationPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        } else if host.withCString({ inet_pton(AF_INET6, $0, &ipv6Destination.sin6_addr) }) == 1 {
            addressFamily = AF_INET6
            protocolNumber = IPPROTO_ICMPV6
            protocolLevel = IPPROTO_IPV6
            boundInterfaceOption = IPV6_BOUND_IF
            echoRequestType = 128
            echoReplyType = 129
            connectSocket = { [self] in
                withUnsafePointer(to: &ipv6Destination) { destinationPointer in
                    destinationPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
        } else {
            finish(.failure(probeError("ICMP validation requires a numeric IPv4 or IPv6 address.")))
            return
        }

        descriptor = Darwin.socket(addressFamily, SOCK_DGRAM, protocolNumber)
        guard descriptor >= 0 else {
            finish(.failure(probeError("Could not create the ICMP validation socket.", errnoValue: errno)))
            return
        }

        var interfaceIndex = if_nametoindex(interfaceName)
        guard interfaceIndex != 0,
              setsockopt(
                descriptor,
                protocolLevel,
                boundInterfaceOption,
                &interfaceIndex,
                socklen_t(MemoryLayout.size(ofValue: interfaceIndex))
              ) == 0 else {
            finish(.failure(probeError("Could not bind the ICMP probe to the tunnel interface.", errnoValue: errno)))
            return
        }

        let connectResult = connectSocket()
        guard connectResult == 0 else {
            finish(.failure(probeError("Could not connect the ICMP validation socket.", errnoValue: errno)))
            return
        }

        let packet = makeEchoRequest(type: echoRequestType, requiresChecksum: addressFamily == AF_INET)
        let sent = packet.withUnsafeBytes { bytes in
            Darwin.send(descriptor, bytes.baseAddress, bytes.count, 0)
        }
        guard sent == packet.count else {
            finish(.failure(probeError("Could not send the ICMP validation packet.", errnoValue: errno)))
            return
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        let ownedDescriptor = descriptor
        source.setEventHandler { [self] in
            receiveReply()
        }
        // Close the descriptor only from the source's cancel handler, i.e. once
        // GCD has fully torn down the kevent. Closing it eagerly (in finish())
        // would let the next probe attempt's socket() reuse the fd number while
        // this source's cancellation is still pending; that late cancellation
        // would then tear down the new source and silently drop its echo reply.
        source.setCancelHandler {
            Darwin.close(ownedDescriptor)
        }
        readSource = source
        source.resume()

        let timeoutWorkItem = DispatchWorkItem { [self] in
            self.finish(.failure(self.probeError("ICMP probe timed out after \(self.timeout)s.")))
        }
        self.timeoutWorkItem = timeoutWorkItem
        queue.asyncAfter(deadline: .now() + timeout, execute: timeoutWorkItem)
    }

    private func receiveReply() {
        var buffer = [UInt8](repeating: 0, count: 2_048)
        let count = Darwin.recv(descriptor, &buffer, buffer.count, 0)
        guard count > 0 else {
            if errno != EAGAIN && errno != EINTR {
                finish(.failure(probeError("Could not receive the ICMP validation reply.", errnoValue: errno)))
            }
            return
        }

        let response = Array(buffer.prefix(count))
        let headerOffset: Int
        if response.count >= 20, response[0] >> 4 == 4 {
            headerOffset = Int(response[0] & 0x0f) * 4
        } else if response.count >= 40, response[0] >> 4 == 6 {
            headerOffset = 40
        } else {
            headerOffset = 0
        }
        guard response.count >= headerOffset + 8 + MemoryLayout<UInt64>.size,
              response[headerOffset] == echoReplyType else {
            return
        }

        let sequenceOffset = headerOffset + 6
        let receivedSequence = UInt16(response[sequenceOffset]) << 8 | UInt16(response[sequenceOffset + 1])
        let nonceBytes = withUnsafeBytes(of: nonce.bigEndian) { Array($0) }
        guard receivedSequence == sequence,
              response.suffix(nonceBytes.count).elementsEqual(nonceBytes) else {
            return
        }
        finish(.success(()))
    }

    private func makeEchoRequest(type: UInt8, requiresChecksum: Bool) -> Data {
        let nonceBytes = withUnsafeBytes(of: nonce.bigEndian) { Array($0) }
        var packet = Data([
            type, 0, 0, 0,
            UInt8(identifier >> 8), UInt8(truncatingIfNeeded: identifier),
            UInt8(sequence >> 8), UInt8(truncatingIfNeeded: sequence)
        ])
        packet.append(contentsOf: nonceBytes)
        if requiresChecksum {
            let checksum = Self.internetChecksum(packet)
            packet[2] = UInt8(checksum >> 8)
            packet[3] = UInt8(truncatingIfNeeded: checksum)
        }
        return packet
    }

    private func finish(_ result: Result<Void, ConnectionError>) {
        guard !isCompleted else {
            return
        }
        isCompleted = true
        timeoutWorkItem?.cancel()
        timeoutWorkItem = nil
        if let readSource {
            readSource.setEventHandler {}
            // The source's cancel handler owns closing the descriptor.
            readSource.cancel()
            self.readSource = nil
            descriptor = -1
        } else if descriptor >= 0 {
            // No source was ever created for this descriptor; close it directly.
            Darwin.close(descriptor)
            descriptor = -1
        }
        completion(result)
    }

    private func probeError(_ message: String, errnoValue: Int32? = nil) -> ConnectionError {
        var diagnostics = ["probe": "ping", "host": host]
        if let errnoValue {
            diagnostics["errno"] = "\(errnoValue)"
        }
        return connectionError(
            .validationFailed,
            stage: .validation,
            message: message,
            diagnostics: diagnostics
        )
    }

    private static func internetChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var index = data.startIndex
        while data.distance(from: index, to: data.endIndex) >= 2 {
            let next = data.index(after: index)
            sum += UInt32(data[index]) << 8 | UInt32(data[next])
            index = data.index(index, offsetBy: 2)
        }
        if index < data.endIndex {
            sum += UInt32(data[index]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return ~UInt16(sum & 0xffff)
    }
}

extension WireGuardLogLevel {
    var osLogLevel: OSLogType {
        switch self {
        case .verbose:
            .debug
        case .error:
            .error
        }
    }
}
