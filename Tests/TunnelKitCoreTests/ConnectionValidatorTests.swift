//
//  ConnectionValidatorTests.swift
//  TunnelKitCoreTests
//
//  Copyright (c) 2026 Davide De Rosa. All rights reserved.
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

import XCTest
import os
@testable import TunnelKitCore

/// Simulates a tunnel data path for validation tests.
final class MockProbeTransport: ConnectionProbeTransport, @unchecked Sendable {

    enum Mode {

        /// Replies to every ICMP/DNS probe.
        case reply

        /// Never replies; a black-holed tunnel.
        case silent

        /// Replies only to ICMP probes, drops DNS.
        case icmpOnly

        /// Starts silent, replies from the given 1-based send attempt on.
        case replyFromAttempt(Int)

        /// Replies to the first `count` probes, then goes silent.
        case replyFirst(Int)

        /// Replies only to probes whose 1-based send attempt is included.
        case replyOnAttempts(Set<Int>)

        /// Pushes unrelated inbound packets whenever an observer is installed.
        case unrelatedNoise
    }

    private struct State {
        var observer: (@Sendable ([Data]) -> Void)?

        var observerToken = 0

        var sendCount = 0

        var sentPackets: [Data] = []
    }

    var mode: Mode

    private let state = OSAllocatedUnfairLock(initialState: State())

    init(mode: Mode) {
        self.mode = mode
    }

    var sendCount: Int {
        state.withLock { $0.sendCount }
    }

    var sentPackets: [Data] {
        state.withLock { $0.sentPackets }
    }

    var observerIsNil: Bool {
        state.withLock { $0.observer == nil }
    }

    func sendProbePackets(_ packets: [Data]) {
        let (observer, attempt): ((@Sendable ([Data]) -> Void)?, Int) = state.withLock {
            $0.sendCount += 1
            $0.sentPackets.append(contentsOf: packets)
            return ($0.observer, $0.sendCount)
        }
        guard let observer else {
            return
        }

        let shouldReply: Bool
        switch mode {
        case .reply, .icmpOnly:
            shouldReply = true

        case .silent, .unrelatedNoise:
            shouldReply = false

        case .replyFromAttempt(let from):
            shouldReply = attempt >= from

        case .replyFirst(let count):
            shouldReply = attempt <= count

        case .replyOnAttempts(let attempts):
            shouldReply = attempts.contains(attempt)
        }
        guard shouldReply else {
            return
        }

        for packet in packets {
            guard let reply = makeReply(to: packet) else {
                continue
            }
            observer([reply])
        }
    }

    @discardableResult
    func installInboundPacketObserver(_ observer: @escaping @Sendable ([Data]) -> Void) -> Int {
        let token: Int = state.withLock {
            $0.observerToken += 1
            $0.observer = observer
            return $0.observerToken
        }
        if case .unrelatedNoise = mode {
            // an inbound packet that matches no probe (e.g. a server keepalive)
            observer([Data([0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 99, 0, 0, 10, 8, 0, 1, 10, 8, 0, 2])])
        }
        return token
    }

    func removeInboundPacketObserver(_ token: Int) {
        state.withLock {
            if $0.observerToken == token {
                $0.observer = nil
            }
        }
    }

    /// Builds the appropriate reply by parsing the outbound probe.
    private func makeReply(to packet: Data) -> Data? {
        guard let version = packet.first.map({ $0 >> 4 }) else {
            return nil
        }
        let protocolNumber: UInt8
        let payloadOffset: Int
        switch version {
        case 4:
            guard packet.count >= 20 else {
                return nil
            }
            protocolNumber = packet[9]
            payloadOffset = Int(packet[0] & 0x0F) * 4

        case 6:
            guard packet.count >= 40 else {
                return nil
            }
            protocolNumber = packet[6]
            payloadOffset = 40

        default:
            return nil
        }
        switch protocolNumber {
        case 1: // ICMP echo request → echo reply with same identifier
            guard packet.count >= payloadOffset + 8 else {
                return nil
            }
            let identifier = UInt16(packet[payloadOffset + 4]) << 8 | UInt16(packet[payloadOffset + 5])
            let sequence = UInt16(packet[payloadOffset + 6]) << 8 | UInt16(packet[payloadOffset + 7])
            return swappingAddresses(
                in: makeEchoReply(identifier: identifier, sequence: sequence),
                with: packet,
                version: version
            )

        case 58: // ICMPv6 echo request
            guard packet.count >= payloadOffset + 8 else {
                return nil
            }
            let identifier = UInt16(packet[payloadOffset + 4]) << 8 | UInt16(packet[payloadOffset + 5])
            let sequence = UInt16(packet[payloadOffset + 6]) << 8 | UInt16(packet[payloadOffset + 7])
            return swappingAddresses(
                in: makeEchoReplyIPv6(identifier: identifier, sequence: sequence),
                with: packet,
                version: version
            )

        case 17: // DNS query → response to the same port/txid
            if case .icmpOnly = mode {
                return nil
            }
            guard packet.count >= payloadOffset + 10 else {
                return nil
            }
            let sourcePort = UInt16(packet[payloadOffset]) << 8 | UInt16(packet[payloadOffset + 1])
            let transactionId = UInt16(packet[payloadOffset + 8]) << 8 | UInt16(packet[payloadOffset + 9])
            if version == 6 {
                return swappingAddresses(
                    in: makeDNSResponseIPv6(toPort: sourcePort, transactionId: transactionId),
                    with: packet,
                    version: version
                )
            }
            return swappingAddresses(
                in: makeDNSResponse(toPort: sourcePort, transactionId: transactionId),
                with: packet,
                version: version
            )

        default:
            return nil
        }
    }

    private func swappingAddresses(in reply: Data, with request: Data, version: UInt8) -> Data {
        var reply = reply
        switch version {
        case 4:
            guard request.count >= 20, reply.count >= 20 else {
                return reply
            }
            reply.replaceSubrange(12..<16, with: request[16..<20])
            reply.replaceSubrange(16..<20, with: request[12..<16])

        case 6:
            guard request.count >= 40, reply.count >= 40 else {
                return reply
            }
            reply.replaceSubrange(8..<24, with: request[24..<40])
            reply.replaceSubrange(24..<40, with: request[8..<24])

        default:
            break
        }
        return reply
    }
}

final class ConnectionValidatorTests: XCTestCase {

    private let context = ConnectionValidationContext(
        localIPv4: "10.8.0.2",
        gatewayIPv4: "10.8.0.1",
        dnsServers: ["10.8.0.1"]
    )

    private func makeOptions(
        probes: [ConnectionValidationOptions.Probe] = [.ping(host: "1.1.1.1")],
        policy: ConnectionValidationOptions.Policy = .any,
        stabilization: TimeInterval = 0,
        strict: Bool = true
    ) -> ConnectionValidationOptions {
        var options = ConnectionValidationOptions()
        options.probes = probes
        options.policy = policy
        options.stabilizationPeriod = stabilization
        options.failsWhenUnverifiable = strict
        return options
    }

    /// Runs validation while continuously advancing the test clock, so
    /// timeout paths execute without real waiting.
    private func validateDriven(
        _ validator: ConnectionValidator,
        clock: TestClock,
        context: ConnectionValidationContext
    ) async -> ConnectionValidator.Outcome {
        let task = Task {
            await validator.validate(context: context)
        }
        let driver = Task {
            for _ in 0..<400 {
                await clock.advance(by: .milliseconds(500))
            }
        }
        let outcome = await task.value
        driver.cancel()
        return outcome
    }

    // MARK: Success paths

    func test_passes_whenExternalHostAnswersPing() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let validator = ConnectionValidator(options: makeOptions(), transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .passed(let evidence) = outcome else {
            return XCTFail("Expected .passed, got \(outcome)")
        }
        XCTAssertTrue(evidence.contains { $0.hasPrefix("ping(") })
    }

    func test_gatewayAloneNeverCountsAsEndToEndEvidence() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let validator = ConnectionValidator(
            options: makeOptions(probes: [.gatewayPing]),
            transport: transport,
            clock: clock
        )

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected gateway-only configuration to fail, got \(outcome)")
        }
        XCTAssertEqual(error.code, .invalidConfiguration)
        XCTAssertEqual(error.diagnostics["reason"], "gatewayOnly")
        XCTAssertEqual(transport.sendCount, 0)
    }

    func test_defaultUsesExternalDNSProbe() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        var options = ConnectionValidationOptions.default
        options.stabilizationPeriod = 0
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .passed(let evidence) = outcome else {
            return XCTFail("Expected default external DNS probe to pass, got \(outcome)")
        }
        XCTAssertTrue(evidence.contains("dns(example.com)"))
    }

    func test_passes_whenDNSResponds() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let validator = ConnectionValidator(
            options: makeOptions(probes: [.dns(hostname: "probe.example", server: nil)]),
            transport: transport,
            clock: clock
        )

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .passed(let evidence) = outcome else {
            return XCTFail("Expected .passed, got \(outcome)")
        }
        XCTAssertTrue(evidence.contains("dns(probe.example)"))
    }

    func test_passesOverIPv6OnlyTunnel() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let options = makeOptions(probes: [.ping(host: "2606:4700:4700::1111")])
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)
        let ipv6Context = ConnectionValidationContext(
            localIPv4: nil,
            gatewayIPv4: nil,
            dnsServers: ["2001:4860:4860::8888"],
            localIPv6: "fd00::2",
            gatewayIPv6: "fd00::1"
        )

        let outcome = await validateDriven(validator, clock: clock, context: ipv6Context)

        guard case .passed = outcome else {
            return XCTFail("Expected IPv6 end-to-end probe to pass, got \(outcome)")
        }
        XCTAssertEqual(transport.sentPackets.first?.first.map { $0 >> 4 }, 6)
    }

    func test_dnsProbeChoosesMatchingIPv6Server() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let options = makeOptions(probes: [.dns(hostname: "example.com", server: nil)])
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)
        let ipv6Context = ConnectionValidationContext(
            localIPv4: nil,
            gatewayIPv4: nil,
            dnsServers: ["2001:4860:4860::8888"],
            localIPv6: "fd00::2"
        )

        let outcome = await validateDriven(validator, clock: clock, context: ipv6Context)

        guard case .passed = outcome else {
            return XCTFail("Expected IPv6 DNS probe to pass, got \(outcome)")
        }
        XCTAssertEqual(transport.sentPackets.first?.first.map { $0 >> 4 }, 6)
    }

    func test_passes_afterTransientFailure() async {
        let clock = TestClock()
        // first probe attempt is lost, second is answered
        let transport = MockProbeTransport(mode: .replyFromAttempt(2))
        let validator = ConnectionValidator(options: makeOptions(), transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .passed = outcome else {
            return XCTFail("Expected .passed after retry, got \(outcome)")
        }
        XCTAssertGreaterThanOrEqual(transport.sendCount, 2)
    }

    func test_unrelatedInboundTrafficNeverCountsAsSuccess() async {
        let clock = TestClock()
        // probes unanswered, but the server pushes keepalive-like packets
        let transport = MockProbeTransport(mode: .unrelatedNoise)
        let validator = ConnectionValidator(options: makeOptions(), transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected unrelated traffic to fail, got \(outcome)")
        }
        XCTAssertEqual(error.code, .validationFailed)
        XCTAssertEqual(error.diagnostics["sawInboundTraffic"], "true")
    }

    // MARK: Failure paths

    func test_fails_whenTunnelIsBlackholed() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .silent)
        var options = makeOptions()
        options.treatsInboundTrafficAsSuccess = false
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected .failed, got \(outcome)")
        }
        XCTAssertEqual(error.code, .validationFailed)
        XCTAssertEqual(error.stage, .validation)
        // all attempts must actually have been made
        XCTAssertGreaterThanOrEqual(transport.sendCount, 3)
    }

    func test_fails_whenControlProbeUnreachable_policyAll() async {
        let clock = TestClock()
        // ICMP works but the DNS control endpoint is down; .all must fail
        let transport = MockProbeTransport(mode: .icmpOnly)
        var options = makeOptions(
            probes: [.gatewayPing, .dns(hostname: "probe.example", server: nil)],
            policy: .all
        )
        options.treatsInboundTrafficAsSuccess = false
        options.probeAttempts = 1
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected .failed with .all policy, got \(outcome)")
        }
        XCTAssertEqual(error.code, .validationFailed)
        XCTAssertTrue(error.diagnostics["failedProbes"]?.contains("dns") ?? false)
    }

    func test_passes_whenOneProbeWorks_policyAny() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .icmpOnly)
        let options = makeOptions(
            probes: [.dns(hostname: "probe.example", server: nil), .ping(host: "1.1.1.1")],
            policy: .any
        )
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .passed(let evidence) = outcome else {
            return XCTFail("Expected .passed with .any policy, got \(outcome)")
        }
        XCTAssertTrue(evidence.contains { $0.hasPrefix("ping(") })
    }

    // MARK: Unverifiable tunnels

    func test_failsClosed_whenNoAddressesAreUsable() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .silent)
        let noIPv4 = ConnectionValidationContext(localIPv4: nil, gatewayIPv4: nil, dnsServers: [])
        let validator = ConnectionValidator(options: makeOptions(), transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: noIPv4)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected fail-closed outcome, got \(outcome)")
        }
        XCTAssertEqual(error.code, .invalidConfiguration)
    }

    func test_strictFail_whenNoProbesUsable() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .silent)
        let noIPv4 = ConnectionValidationContext(localIPv4: nil, gatewayIPv4: nil, dnsServers: [])
        let validator = ConnectionValidator(options: makeOptions(strict: true), transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: noIPv4)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected .failed in strict mode, got \(outcome)")
        }
        XCTAssertEqual(error.code, .invalidConfiguration)
    }

    func test_compatibilityFlagCannotEnableUnverifiedSuccess() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .silent)
        let noAddresses = ConnectionValidationContext(localIPv4: nil, gatewayIPv4: nil, dnsServers: [])
        var options = makeOptions(strict: false)
        options.failsWhenUnverifiable = false
        options.treatsInboundTrafficAsSuccess = true
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: noAddresses)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected enabled validation to stay fail-closed, got \(outcome)")
        }
        XCTAssertEqual(error.code, .invalidConfiguration)
    }

    func test_customPingCannotTargetTunnelGateway() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let options = makeOptions(probes: [.ping(host: "10.8.0.1")])
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected local target to be rejected, got \(outcome)")
        }
        XCTAssertEqual(error.code, .invalidConfiguration)
        XCTAssertEqual(transport.sendCount, 0)
    }

    func test_invalidOptionsFailBeforeSendingPackets() async {
        let transport = MockProbeTransport(mode: .reply)
        var options = makeOptions()
        options.probeAttempts = 0
        options.probeTimeout = .nan
        let validator = ConnectionValidator(options: options, transport: transport, clock: TestClock())

        let outcome = await validator.validate(context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected invalid configuration, got \(outcome)")
        }
        XCTAssertEqual(error.code, .invalidConfiguration)
        XCTAssertTrue(error.diagnostics["invalidFields"]?.contains("probeTimeout") ?? false)
        XCTAssertTrue(error.diagnostics["invalidFields"]?.contains("probeAttempts") ?? false)
        XCTAssertEqual(transport.sendCount, 0)
    }

    // MARK: Stabilization

    func test_stabilization_confirmsHealthyTunnel() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let validator = ConnectionValidator(
            options: makeOptions(stabilization: 2.0),
            transport: transport,
            clock: clock
        )

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .passed(let evidence) = outcome else {
            return XCTFail("Expected .passed after stabilization, got \(outcome)")
        }
        XCTAssertTrue(evidence.contains("stabilized"))
    }

    func test_stabilizationRetriesTransientDNSLoss() async {
        let clock = TestClock()
        // Initial validation succeeds, the first stabilization packet is lost,
        // and the retry succeeds.
        let transport = MockProbeTransport(mode: .replyOnAttempts([1, 3]))
        var options = makeOptions(
            probes: [.dns(hostname: "probe.example", server: nil)],
            stabilization: 2.0
        )
        options.probeAttempts = 3
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .passed(let evidence) = outcome else {
            return XCTFail("Expected stabilization retry to recover, got \(outcome)")
        }
        XCTAssertTrue(evidence.contains("stabilized"))
        XCTAssertEqual(transport.sendCount, 3)
    }

    func test_stabilization_failsWhenTunnelDiesRightAfterConnect() async {
        let clock = TestClock()
        // answers the initial probe, then the server goes dark
        let transport = MockProbeTransport(mode: .replyFirst(1))
        var options = makeOptions(stabilization: 2.0)
        options.treatsInboundTrafficAsSuccess = false
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected .failed when tunnel dies during stabilization, got \(outcome)")
        }
        XCTAssertEqual(error.code, .validationFailed)
        XCTAssertEqual(error.diagnostics["phase"], "stabilization")
        XCTAssertEqual(transport.sendCount, 4)
    }

    func test_maxDurationIncludesStabilizationAndRecheck() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        var options = makeOptions(stabilization: 10)
        options.maxDuration = 1
        let validator = ConnectionValidator(options: options, transport: transport, clock: clock)

        let outcome = await validateDriven(validator, clock: clock, context: context)

        guard case .failed(let error) = outcome else {
            return XCTFail("Expected whole-operation deadline, got \(outcome)")
        }
        XCTAssertEqual(error.code, .validationFailed)
        XCTAssertEqual(error.diagnostics["deadline"], "maxDuration")
    }

    // MARK: Cancellation and configuration

    func test_cancellation_returnsCancelled() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .silent)
        let validator = ConnectionValidator(options: makeOptions(), transport: transport, clock: clock)

        let context = self.context
        let task = Task {
            await validator.validate(context: context)
        }
        await clock.megaYield()
        task.cancel()
        let outcome = await task.value

        switch outcome {
        case .cancelled:
            break

        case .failed, .passed, .passedUnverified, .skipped:
            XCTFail("Expected .cancelled, got \(outcome)")
        }
    }

    func test_cancellationNeverReportsTimeoutFailure() async {
        // repeatedly cancel a silent (never-completing) validation; it must
        // always yield .cancelled, never a spurious .failed(timeout)
        for _ in 0..<40 {
            let transport = MockProbeTransport(mode: .silent)
            let validator = ConnectionValidator(options: makeOptions(), transport: transport, clock: ContinuousClock())
            let context = self.context
            let task = Task {
                await validator.validate(context: context)
            }
            await Task.yield()
            task.cancel()
            let outcome = await task.value
            if case .failed(let error) = outcome {
                XCTFail("Cancellation surfaced as failure: \(error)")
                return
            }
        }
    }

    func test_disabledValidation_isSkipped() async {
        let transport = MockProbeTransport(mode: .silent)
        let validator = ConnectionValidator(options: .disabled, transport: transport, clock: TestClock())

        let outcome = await validator.validate(context: context)

        guard case .skipped = outcome else {
            return XCTFail("Expected .skipped, got \(outcome)")
        }
        XCTAssertEqual(transport.sendCount, 0)
    }

    func test_observerIsRemovedAfterValidation() async {
        let clock = TestClock()
        let transport = MockProbeTransport(mode: .reply)
        let validator = ConnectionValidator(options: makeOptions(), transport: transport, clock: clock)

        _ = await validateDriven(validator, clock: clock, context: context)

        let observerGone: Bool = transport.observerIsNil
        XCTAssertTrue(observerGone, "Observer must be removed after validation")
    }
}
