//
//  ConnectionValidator.swift
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
import os
import SwiftyBeaver

private let log = SwiftyBeaver.self

/// Ability to inject probe packets into a tunnel and observe inbound packets.
public protocol ConnectionProbeTransport: AnyObject {

    /// Injects raw IP packets into the tunnel as if they originated locally.
    func sendProbePackets(_ packets: [Data])

    /**
     Installs an observer for decrypted inbound tunnel packets.

     Only one observer is active at a time. A stale removal token must not
     remove a newer observer.
     */
    @discardableResult
    func installInboundPacketObserver(_ observer: @escaping @Sendable ([Data]) -> Void) -> Int

    /// Removes the observer identified by `token` if it is still current.
    func removeInboundPacketObserver(_ token: Int)
}

/// Configuration of end-to-end tunnel connectivity validation.
public struct ConnectionValidationOptions: Codable, Equatable, Sendable {

    /// A single connectivity check.
    public enum Probe: Codable, Equatable, Sendable {

        /// ICMP echo to the tunnel-provided gateway.
        ///
        /// This is useful diagnostics, but it is not end-to-end evidence and
        /// can never establish connectivity on its own.
        case gatewayPing

        /// ICMP echo to a numeric IPv4 or IPv6 address reached through the tunnel.
        case ping(host: String)

        /// DNS A query for `hostname` via `server` (`nil` uses tunnel DNS).
        ///
        /// Only a successful response containing an answer counts. NXDOMAIN,
        /// REFUSED, SERVFAIL and empty responses are failures.
        case dns(hostname: String, server: String?)
    }

    /// How configured probe results combine.
    public enum Policy: String, Codable, Sendable {

        /// Validation passes when any end-to-end probe succeeds.
        case any

        /// Validation requires every configured probe to succeed, including
        /// diagnostic gateway probes, plus at least one end-to-end probe.
        case all
    }

    /// Master switch. Disabling validation explicitly restores legacy behavior.
    public var isEnabled = true

    /// Probes to run. The default verifies external DNS resolution through the tunnel.
    public var probes: [Probe] = [.dns(hostname: "example.com", server: nil)]

    /// How probe results combine.
    public var policy: Policy = .any

    /// Seconds to wait for a reply to one probe attempt.
    public var probeTimeout: TimeInterval = 4.0

    /// Number of attempts per probe during initial validation and the
    /// stabilization recheck.
    public var probeAttempts: Int = 3

    /// Retained for configuration compatibility.
    ///
    /// Inbound traffic is recorded as diagnostics, but never counts as
    /// end-to-end success because server-originated traffic does not prove
    /// access to an external endpoint.
    public var treatsInboundTrafficAsSuccess = false

    /// Retained for configuration compatibility.
    ///
    /// Enabled validation is always fail-closed when no end-to-end probe is
    /// usable. `.disabled` is the only opt-out.
    public var failsWhenUnverifiable = true

    /// Seconds to wait before rechecking the successful probes.
    public var stabilizationPeriod: TimeInterval = 2.0

    /// Seconds to wait after the tunnel is established before sending the first
    /// probe, letting the data path settle so an early probe does not spuriously
    /// fail on a freshly-connected tunnel. `0` probes immediately.
    public var warmupPeriod: TimeInterval = 0

    /// Seconds to wait for an asynchronously reported protocol handshake.
    public var handshakeTimeout: TimeInterval = 15.0

    /// Hard cap for configuration, all attempts, stabilization and recheck.
    public var maxDuration: TimeInterval = 25.0

    /// Fail-closed validation with a stable, reserved external DNS endpoint.
    public static let `default` = ConnectionValidationOptions()

    /// Requires every configured signal and at least one end-to-end probe.
    public static let strict: ConnectionValidationOptions = {
        var options = ConnectionValidationOptions()
        options.policy = .all
        return options
    }()

    /// Legacy behavior: no connectivity validation.
    public static let disabled: ConnectionValidationOptions = {
        var options = ConnectionValidationOptions()
        options.isEnabled = false
        return options
    }()

    public init() {
    }
}

/// Tunnel-specific addresses used to build IPv4 and IPv6 probes.
public struct ConnectionValidationContext: Sendable {

    public let localIPv4: String?

    public let gatewayIPv4: String?

    public let dnsServers: [String]

    public let localIPv6: String?

    public let gatewayIPv6: String?

    /**
     Creates a validation context.

     IPv6 parameters follow the original IPv4/DNS parameters and have defaults,
     preserving source compatibility with the IPv4-only initializer.
     */
    public init(
        localIPv4: String?,
        gatewayIPv4: String?,
        dnsServers: [String],
        localIPv6: String? = nil,
        gatewayIPv6: String? = nil
    ) {
        self.localIPv4 = localIPv4
        self.gatewayIPv4 = gatewayIPv4
        self.dnsServers = dnsServers
        self.localIPv6 = localIPv6
        self.gatewayIPv6 = gatewayIPv6
    }
}

/// Proves that a formally established tunnel reaches a configured external
/// endpoint before the provider may report it as connected.
public final class ConnectionValidator: @unchecked Sendable {

    /// The verdict of a validation run.
    public enum Outcome: Sendable {

        /// At least one end-to-end probe succeeded and the policy was met.
        case passed(evidence: [String])

        /// Retained for ABI compatibility. The fail-closed validator never
        /// produces this outcome while validation is enabled.
        case passedUnverified(reason: String)

        /// Connectivity or validation configuration failed.
        case failed(ConnectionError)

        /// The attempt was superseded or torn down.
        case cancelled

        /// Validation was explicitly disabled.
        case skipped
    }

    private enum ProbeScope {
        case gateway

        case endToEnd
    }

    private struct ProbePlan {
        let name: String

        let scope: ProbeScope

        let request: Data

        let matches: @Sendable (Data) -> Bool
    }

    private enum ReplyResult: Sendable {
        case matched

        case sawInboundTraffic

        case silence
    }

    private enum DeadlineRaceResult<Value: Sendable>: Sendable {
        case value(Value)

        case deadline

        case timerCancelled
    }

    private let options: ConnectionValidationOptions

    private let transport: ConnectionProbeTransport

    private let clock: any Clock<Duration>

    public init(
        options: ConnectionValidationOptions,
        transport: ConnectionProbeTransport,
        clock: any Clock<Duration> = ContinuousClock()
    ) {
        self.options = options
        self.transport = transport
        self.clock = clock
    }

    /**
     Runs validation within one absolute operation budget.

     The `maxDuration` deadline includes option validation, every retry,
     stabilization and the final recheck.
     */
    public func validate(context: ConnectionValidationContext) async -> Outcome {
        guard options.isEnabled else {
            log.info("Validation: skipped (disabled by configuration)")
            return .skipped
        }
        if let configurationError = validateOptions() {
            return .failed(configurationError)
        }

        let plans: [ProbePlan]
        switch makeProbePlans(for: context) {
        case .success(let configuredPlans):
            plans = configuredPlans

        case .failure(let error):
            return .failed(error)
        }

        log.info("Validation: starting with \(plans.count) probe(s), policy=\(options.policy.rawValue)")
        let outcome = await withDeadline(seconds: options.maxDuration) {
            await self.validateAndStabilize(plans)
        } onDeadline: {
            .failed(ConnectionError(
                .validationFailed,
                stage: .validation,
                message: "Connectivity validation exceeded its \(self.options.maxDuration)s operation deadline.",
                diagnostics: [
                    "deadline": "maxDuration",
                    "maxDuration": String(self.options.maxDuration)
                ]
            ))
        }
        return Task.isCancelled ? .cancelled : outcome
    }

    // MARK: Configuration

    private func validateOptions() -> ConnectionError? {
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
        if !options.warmupPeriod.isFinite || options.warmupPeriod < 0 {
            invalidFields.append("warmupPeriod")
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
        guard invalidFields.isEmpty else {
            return ConnectionError(
                .invalidConfiguration,
                stage: .validation,
                message: "Connectivity validation options are invalid.",
                diagnostics: ["invalidFields": invalidFields.joined(separator: ",")]
            )
        }
        return nil
    }

    private func makeProbePlans(for context: ConnectionValidationContext) -> Result<[ProbePlan], ConnectionError> {
        var plans: [ProbePlan] = []
        for (index, probe) in options.probes.enumerated() {
            let plan: ProbePlan?
            switch probe {
            case .gatewayPing:
                plan = makeGatewayPlan(context: context, sequence: UInt16(index + 1))

            case .ping(let host):
                guard ProbePacket.isNumericIPAddress(host) else {
                    return .failure(invalidProbeError(
                        index: index,
                        reason: "A custom ping target must be a numeric IPv4 or IPv6 address."
                    ))
                }
                guard !isTunnelLocalAddress(host, context: context) else {
                    return .failure(invalidProbeError(
                        index: index,
                        reason: "A custom ping target must not be the tunnel address or gateway."
                    ))
                }
                plan = makePingPlan(
                    name: "ping(\(host.maskedDescription))",
                    scope: .endToEnd,
                    destination: host,
                    context: context,
                    sequence: UInt16(index + 1)
                )

            case .dns(let hostname, let server):
                guard ProbePacket.isValidDNSHostname(hostname) else {
                    return .failure(invalidProbeError(
                        index: index,
                        reason: "The DNS hostname is empty, malformed or too long."
                    ))
                }
                let configuredServers = server.map { [$0] } ?? context.dnsServers
                guard !configuredServers.isEmpty else {
                    return .failure(invalidProbeError(
                        index: index,
                        reason: "The DNS probe has no tunnel DNS server."
                    ))
                }
                guard configuredServers.contains(where: ProbePacket.isNumericIPAddress) else {
                    return .failure(invalidProbeError(
                        index: index,
                        reason: "DNS servers must be numeric IPv4 or IPv6 addresses."
                    ))
                }
                plan = makeDNSPlan(
                    hostname: hostname,
                    explicitServer: server,
                    context: context
                )
            }
            guard let plan else {
                return .failure(invalidProbeError(
                    index: index,
                    reason: "The probe has no valid same-family local and destination addresses."
                ))
            }
            plans.append(plan)
        }

        guard plans.contains(where: { $0.scope == .endToEnd }) else {
            return .failure(ConnectionError(
                .invalidConfiguration,
                stage: .validation,
                message: "At least one custom end-to-end ping or DNS probe is required.",
                diagnostics: ["reason": "gatewayOnly"]
            ))
        }
        return .success(plans)
    }

    private func makeGatewayPlan(context: ConnectionValidationContext, sequence: UInt16) -> ProbePlan? {
        if let gateway = context.gatewayIPv4 {
            return makePingPlan(
                name: "gatewayPing",
                scope: .gateway,
                destination: gateway,
                context: context,
                sequence: sequence
            )
        }
        if let gateway = context.gatewayIPv6 {
            return makePingPlan(
                name: "gatewayPing",
                scope: .gateway,
                destination: gateway,
                context: context,
                sequence: sequence
            )
        }
        return nil
    }

    private func makePingPlan(
        name: String,
        scope: ProbeScope,
        destination: String,
        context: ConnectionValidationContext,
        sequence: UInt16
    ) -> ProbePlan? {
        let identifier = UInt16.random(in: .min ... .max)
        let sourceCandidates = [context.localIPv4, context.localIPv6].compactMap { $0 }
        for source in sourceCandidates {
            guard let request = ProbePacket.icmpEchoRequest(
                source: source,
                destination: destination,
                identifier: identifier,
                sequence: sequence
            ) else {
                continue
            }
            return ProbePlan(name: name, scope: scope, request: request) { packet in
                ProbePacket.isICMPEchoReply(
                    packet,
                    identifier: identifier,
                    sequence: sequence,
                    source: destination,
                    destination: source
                )
            }
        }
        return nil
    }

    private func makeDNSPlan(
        hostname: String,
        explicitServer: String?,
        context: ConnectionValidationContext
    ) -> ProbePlan? {
        let servers = explicitServer.map { [$0] } ?? context.dnsServers
        let sources = [context.localIPv4, context.localIPv6].compactMap { $0 }
        let sourcePort = UInt16.random(in: 20_000...60_000)
        let transactionId = UInt16.random(in: .min ... .max)

        for server in servers {
            for source in sources {
                guard let request = ProbePacket.dnsQuery(
                    source: source,
                    destination: server,
                    sourcePort: sourcePort,
                    transactionId: transactionId,
                    hostname: hostname
                ) else {
                    continue
                }
                return ProbePlan(name: "dns(\(hostname))", scope: .endToEnd, request: request) { packet in
                    ProbePacket.isDNSResponse(
                        packet,
                        sourcePort: sourcePort,
                        transactionId: transactionId,
                        source: server,
                        destination: source
                    )
                }
            }
        }
        return nil
    }

    private func isTunnelLocalAddress(_ address: String, context: ConnectionValidationContext) -> Bool {
        [context.localIPv4, context.gatewayIPv4, context.localIPv6, context.gatewayIPv6]
            .compactMap { $0 }
            .contains { ProbePacket.addressesEqual(address, $0) }
    }

    private func invalidProbeError(index: Int, reason: String) -> ConnectionError {
        ConnectionError(
            .invalidConfiguration,
            stage: .validation,
            message: "Connectivity probe \(index) is not usable.",
            diagnostics: [
                "probeIndex": String(index),
                "reason": reason
            ]
        )
    }

    // MARK: Probe execution

    private func validateAndStabilize(_ plans: [ProbePlan]) async -> Outcome {
        if options.warmupPeriod > 0 {
            log.info("Validation: warming up for \(options.warmupPeriod)s before probing")
            do {
                try await clock.sleep(for: .seconds(options.warmupPeriod))
            } catch {
                return .cancelled
            }
            guard !Task.isCancelled else {
                return .cancelled
            }
        }
        let initialOutcome = await runProbes(plans)
        guard case .passed(let evidence) = initialOutcome else {
            return initialOutcome
        }
        guard options.stabilizationPeriod > 0 else {
            return initialOutcome
        }

        log.info("Validation: stabilizing for \(options.stabilizationPeriod)s")
        do {
            try await clock.sleep(for: .seconds(options.stabilizationPeriod))
        } catch {
            return .cancelled
        }
        guard !Task.isCancelled else {
            return .cancelled
        }

        switch await runProbes(plans) {
        case .passed(let recheckEvidence):
            return .passed(evidence: evidence + ["stabilized"] + recheckEvidence)

        case .cancelled:
            return .cancelled

        case .failed, .passedUnverified, .skipped:
            return .failed(ConnectionError(
                .validationFailed,
                stage: .validation,
                message: "The tunnel stopped reaching its end-to-end probe during stabilization.",
                diagnostics: ["phase": "stabilization"]
            ))
        }
    }

    private func runProbes(_ plans: [ProbePlan]) async -> Outcome {
        let attempts = options.probeAttempts
        var evidence: [String] = []
        var endToEndEvidence: [String] = []
        var failedProbes: [String] = []
        var sawInboundTraffic = false

        for plan in plans {
            guard !Task.isCancelled else {
                return .cancelled
            }
            var passed = false
            for attempt in 1...attempts {
                let result = await sendAndAwaitReply(plan)
                guard !Task.isCancelled else {
                    return .cancelled
                }
                switch result {
                case .matched:
                    log.info("Validation: probe \(plan.name) succeeded (attempt \(attempt))")
                    evidence.append(plan.name)
                    if plan.scope == .endToEnd {
                        endToEndEvidence.append(plan.name)
                    }
                    passed = true

                case .sawInboundTraffic:
                    sawInboundTraffic = true
                    log.debug("Validation: probe \(plan.name) timed out; unrelated inbound traffic was observed")

                case .silence:
                    log.debug("Validation: probe \(plan.name) attempt \(attempt) timed out")
                }
                if passed {
                    break
                }
            }

            if passed {
                if options.policy == .any, plan.scope == .endToEnd {
                    return .passed(evidence: evidence)
                }
            } else {
                failedProbes.append(plan.name)
                if options.policy == .all {
                    break
                }
            }
        }

        if options.policy == .all, failedProbes.isEmpty, !endToEndEvidence.isEmpty {
            return .passed(evidence: evidence)
        }
        return .failed(ConnectionError(
            .validationFailed,
            stage: .validation,
            message: "The tunnel did not reach a configured end-to-end probe.",
            diagnostics: [
                "failedProbes": failedProbes.joined(separator: ","),
                "policy": options.policy.rawValue,
                "attemptsPerProbe": String(attempts),
                "sawInboundTraffic": String(sawInboundTraffic)
            ]
        ))
    }

    private func sendAndAwaitReply(_ plan: ProbePlan) async -> ReplyResult {
        await awaitInbound(
            matching: plan.matches,
            timeout: options.probeTimeout,
            sendPackets: [plan.request]
        )
    }

    private func awaitInbound(
        matching predicate: @escaping @Sendable (Data) -> Bool,
        timeout: TimeInterval,
        sendPackets: [Data]
    ) async -> ReplyResult {
        let sawTraffic = OSAllocatedUnfairLock(initialState: false)
        let observerToken = OSAllocatedUnfairLock<Int?>(initialState: nil)
        let stream = AsyncStream<Void>(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let installedToken = transport.installInboundPacketObserver { packets in
                if packets.contains(where: predicate) {
                    continuation.yield(())
                } else if !packets.isEmpty {
                    sawTraffic.withLock { $0 = true }
                }
            }
            observerToken.withLock { $0 = installedToken }
        }
        defer {
            if let installedToken = observerToken.withLock({ $0 }) {
                transport.removeInboundPacketObserver(installedToken)
            }
        }

        transport.sendProbePackets(sendPackets)
        return await withDeadline(seconds: timeout) {
            for await _ in stream {
                return .matched
            }
            return sawTraffic.withLock { $0 } ? .sawInboundTraffic : .silence
        } onDeadline: {
            sawTraffic.withLock { $0 } ? .sawInboundTraffic : .silence
        }
    }

    /// Races work against the injected clock and cancels the losing branch.
    private func withDeadline<Value: Sendable>(
        seconds: TimeInterval,
        _ body: @escaping @Sendable () async -> Value,
        onDeadline: @escaping @Sendable () -> Value
    ) async -> Value {
        let clock = self.clock
        return await withTaskGroup(of: DeadlineRaceResult<Value>.self) { group in
            group.addTask {
                .value(await body())
            }
            group.addTask {
                do {
                    try await clock.sleep(for: .seconds(seconds))
                    return .deadline
                } catch {
                    return .timerCancelled
                }
            }

            var selectedValue: Value?
            while let result = await group.next() {
                switch result {
                case .value(let value):
                    selectedValue = value

                case .deadline:
                    selectedValue = onDeadline()

                case .timerCancelled:
                    continue
                }
                break
            }
            group.cancelAll()
            return selectedValue ?? onDeadline()
        }
    }
}
