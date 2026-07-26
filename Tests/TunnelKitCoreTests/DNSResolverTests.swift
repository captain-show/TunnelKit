//
//  DNSResolverTests.swift
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
import dnssd
@testable import TunnelKitCore

final class DNSResolverTests: XCTestCase {
    private let queue = DispatchQueue(label: "DNSResolverTests")

    // MARK: Success

    func test_ipv4Literal_resolvesToIPv4() {
        let exp = expectation(description: "resolve")
        DNSResolver.resolve("127.0.0.1", timeout: 5000, queue: queue) { result in
            switch result {
            case .success(let records):
                XCTAssertTrue(records.contains { $0.address == "127.0.0.1" && !$0.isIPv6 })
            case .failure(let error):
                XCTFail("Unexpected failure: \(error)")
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 6)
    }

    func test_ipv6Literal_resolvesToIPv6() {
        let exp = expectation(description: "resolve")
        DNSResolver.resolve("::1", timeout: 5000, queue: queue) { result in
            switch result {
            case .success(let records):
                XCTAssertTrue(records.contains { $0.isIPv6 })
            case .failure(let error):
                XCTFail("Unexpected failure: \(error)")
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 6)
    }

    func test_localhost_resolvesOffline() {
        let exp = expectation(description: "resolve")
        DNSResolver.resolve("localhost", timeout: 5000, queue: queue) { result in
            if case .failure(let error) = result {
                XCTFail("Unexpected failure: \(error)")
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 6)
    }

    func test_emptyHostname_fails() {
        let exp = expectation(description: "resolve")
        let start = Date()
        DNSResolver.resolve("", timeout: 2000, queue: queue) { result in
            switch result {
            case .success:
                XCTFail("Empty hostname must not resolve")

            case .failure(let error):
                guard case TunnelKitCoreError.dnsResolver(.invalidHostname) = error else {
                    XCTFail("Unexpected error: \(error)")
                    exp.fulfill()
                    return
                }
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 3)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)
    }

    func test_negativeTimeoutFailsWithDetailedError() async {
        do {
            _ = try await DNSResolver.resolve("example.com", timeout: -1)
            XCTFail("A negative timeout must fail")
        } catch TunnelKitCoreError.dnsResolver(.invalidTimeout) {
            // expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // MARK: DNS-SD callback batching

    func test_callbackAccumulatorCollectsBothAddressFamilies() {
        var accumulator = DNSReplyAccumulator()
        let ipv4 = DNSRecord(address: "192.0.2.1", isIPv6: false)
        let ipv6 = DNSRecord(address: "2001:db8::1", isIPv6: true)
        let addAndMore = DNSServiceFlags(kDNSServiceFlagsAdd | kDNSServiceFlagsMoreComing)
        let add = DNSServiceFlags(kDNSServiceFlagsAdd)

        XCTAssertEqual(
            accumulator.consume(flags: addAndMore, errorCode: DNSServiceErrorType(kDNSServiceErr_NoError), record: ipv6),
            .wait
        )
        XCTAssertEqual(
            accumulator.consume(flags: add, errorCode: DNSServiceErrorType(kDNSServiceErr_NoError), record: ipv4),
            .settle
        )
        XCTAssertEqual(Set(accumulator.records.map(\.address)), Set(["192.0.2.1", "2001:db8::1"]))
    }

    func test_callbackAccumulatorKeepsResultsAcrossSeparateBatches() {
        var accumulator = DNSReplyAccumulator()
        let add = DNSServiceFlags(kDNSServiceFlagsAdd)

        XCTAssertEqual(
            accumulator.consume(
                flags: add,
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: DNSRecord(address: "192.0.2.1", isIPv6: false)
            ),
            .settle
        )
        XCTAssertEqual(
            accumulator.consume(
                flags: add,
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: DNSRecord(address: "2001:db8::1", isIPv6: true)
            ),
            .settle
        )
        XCTAssertEqual(accumulator.records.count, 2)
    }

    func test_callbackAccumulatorDoesNotTreatEmptyBatchAsAnError() {
        var accumulator = DNSReplyAccumulator()

        XCTAssertEqual(
            accumulator.consume(
                flags: 0,
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: nil
            ),
            .settle
        )
        XCTAssertTrue(accumulator.records.isEmpty)

        XCTAssertEqual(
            accumulator.consume(
                flags: DNSServiceFlags(kDNSServiceFlagsAdd),
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: DNSRecord(address: "192.0.2.1", isIPv6: false)
            ),
            .settle
        )
        XCTAssertEqual(accumulator.records.map(\.address), ["192.0.2.1"])
    }

    func test_callbackAccumulatorSurfacesErrorsImmediately() {
        var accumulator = DNSReplyAccumulator()

        XCTAssertEqual(
            accumulator.consume(
                flags: 0,
                errorCode: DNSServiceErrorType(kDNSServiceErr_ServiceNotRunning),
                record: nil
            ),
            .fail(.service(code: DNSServiceErrorType(kDNSServiceErr_ServiceNotRunning)))
        )
        XCTAssertEqual(
            accumulator.consume(flags: 0, errorCode: DNSServiceErrorType(kDNSServiceErr_Timeout), record: nil),
            .fail(.timeout)
        )
    }

    func test_settlementTimerCannotDeliverEmptyOrReplacementRecords() {
        var accumulator = DNSReplyAccumulator()
        var tracker = DNSSettlementTracker()
        let ipv4 = DNSRecord(address: "192.0.2.1", isIPv6: false)
        let ipv6 = DNSRecord(address: "2001:db8::1", isIPv6: true)
        let add = DNSServiceFlags(kDNSServiceFlagsAdd)

        XCTAssertEqual(
            accumulator.consume(
                flags: add,
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: ipv4
            ),
            .settle
        )
        guard case .schedule(let ipv4Generation) = tracker.update(records: accumulator.records) else {
            return XCTFail("A single address family must schedule settlement")
        }

        XCTAssertEqual(
            accumulator.consume(
                flags: 0,
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: ipv4
            ),
            .settle
        )
        XCTAssertEqual(tracker.update(records: accumulator.records), .wait)
        XCTAssertTrue(accumulator.records.isEmpty)
        XCTAssertFalse(tracker.canFinish(generation: ipv4Generation, records: accumulator.records))

        XCTAssertEqual(
            accumulator.consume(
                flags: add,
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: ipv6
            ),
            .settle
        )
        guard case .schedule(let ipv6Generation) = tracker.update(records: accumulator.records) else {
            return XCTFail("A replacement address family must schedule a new settlement")
        }

        XCTAssertFalse(tracker.canFinish(generation: ipv4Generation, records: accumulator.records))
        XCTAssertTrue(tracker.canFinish(generation: ipv6Generation, records: accumulator.records))
    }

    func test_familySpecificTracker_waitsForRequiredFamilyInsteadOfSettlingOnOther() {
        // A UDP6/TCP6 transport can only dial IPv6. An IPv4-only batch must not
        // settle the resolution, or a dual-stack host whose AAAA arrives late
        // would be reported as a spurious DNS failure.
        var tracker = DNSSettlementTracker(requiredFamily: .ipv6)
        let ipv4 = DNSRecord(address: "192.0.2.1", isIPv6: false)
        let ipv6 = DNSRecord(address: "2001:db8::1", isIPv6: true)

        XCTAssertEqual(tracker.update(records: [ipv4]), .wait)
        XCTAssertEqual(tracker.update(records: [ipv4, ipv6]), .finish)
    }

    func test_familySpecificTracker_finishesImmediatelyWhenRequiredFamilyPresent() {
        var ipv4Tracker = DNSSettlementTracker(requiredFamily: .ipv4)
        let ipv4 = DNSRecord(address: "192.0.2.1", isIPv6: false)
        let ipv6 = DNSRecord(address: "2001:db8::1", isIPv6: true)

        // No grace period is needed when the only usable family already arrived.
        XCTAssertEqual(ipv4Tracker.update(records: [ipv4]), .finish)

        var ipv6Tracker = DNSSettlementTracker(requiredFamily: .ipv4)
        XCTAssertEqual(ipv6Tracker.update(records: [ipv6]), .wait)
    }

    func test_anyFamilyTracker_stillSchedulesGraceForSingleFamily() {
        // The default (dual-stack) behavior is unchanged: a single family
        // schedules the short grace period rather than finishing or waiting.
        var tracker = DNSSettlementTracker()
        let ipv4 = DNSRecord(address: "192.0.2.1", isIPv6: false)

        guard case .schedule = tracker.update(records: [ipv4]) else {
            return XCTFail("A single family must schedule settlement under .any")
        }
        XCTAssertEqual(tracker.update(records: []), .wait)
    }

    func test_incompleteRemovalBatchInvalidatesPriorSettlement() {
        var accumulator = DNSReplyAccumulator()
        var tracker = DNSSettlementTracker()
        let record = DNSRecord(address: "192.0.2.1", isIPv6: false)

        XCTAssertEqual(
            accumulator.consume(
                flags: DNSServiceFlags(kDNSServiceFlagsAdd),
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: record
            ),
            .settle
        )
        guard case .schedule(let scheduledGeneration) = tracker.update(records: accumulator.records) else {
            return XCTFail("A single address family must schedule settlement")
        }

        XCTAssertEqual(
            accumulator.consume(
                flags: DNSServiceFlags(kDNSServiceFlagsMoreComing),
                errorCode: DNSServiceErrorType(kDNSServiceErr_NoError),
                record: record
            ),
            .wait
        )
        tracker.invalidate()

        XCTAssertTrue(accumulator.records.isEmpty)
        XCTAssertFalse(tracker.canFinish(generation: scheduledGeneration, records: accumulator.records))
    }

    // MARK: Timeout / single delivery

    /// A zero-millisecond timeout races the resolver reply on the shared serial
    /// queue. Whichever runs first wins; the loser is swallowed. This
    /// deterministically exercises the "simultaneous timeout and success" race
    /// and asserts exactly-once delivery.
    func test_timeoutRacesSuccess_deliversExactlyOnce() {
        for _ in 0..<50 {
            let exp = expectation(description: "resolve")
            let count = Counter()
            DNSResolver.resolve("127.0.0.1", timeout: 0, queue: queue) { _ in
                count.increment()
                exp.fulfill()
            }
            wait(for: [exp], timeout: 3)
            // give any erroneous second delivery a chance to land
            let settle = expectation(description: "settle")
            queue.asyncAfter(deadline: .now() + .milliseconds(20)) { settle.fulfill() }
            wait(for: [settle], timeout: 1)
            XCTAssertEqual(count.value, 1)
        }
    }

    /// A real lookup with a tiny timeout must return promptly (never block the
    /// caller for the ~30s system DNS timeout the old getaddrinfo path risked).
    func test_timeout_returnsPromptly() {
        let exp = expectation(description: "resolve")
        let start = Date()
        DNSResolver.resolve("this-host-does-not-exist.tunnelkit.invalid", timeout: 200, queue: queue) { result in
            if case .success = result {
                // extremely unlikely, but not a correctness failure
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 3)
        XCTAssertLessThan(Date().timeIntervalSince(start), 3, "resolution must not hold the caller for the system DNS timeout")
    }

    // MARK: Cancellation (async)

    func test_asyncCancellation_throwsPromptly() async {
        let task = Task { () -> [DNSRecord] in
            try await DNSResolver.resolve("this-host-does-not-exist.tunnelkit.invalid", timeout: 30_000)
        }
        task.cancel()
        let start = Date()
        do {
            _ = try await task.value
            // acceptable only if it somehow resolved instantly; otherwise fail below
        } catch is CancellationError {
            // expected
        } catch {
            // a failure/timeout is also acceptable as long as it was prompt
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3, "cancellation must free the resolver immediately")
    }

    func test_cancelledNumericLookupThrowsCancellation() async {
        let task = Task { try await DNSResolver.resolve("127.0.0.1", timeout: 5_000) }
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("A cancelled lookup must not return a cached numeric result")
        } catch is CancellationError {
            // expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func test_asyncSuccess_ipv4() async throws {
        let records = try await DNSResolver.resolve("127.0.0.1", timeout: 5000)
        XCTAssertTrue(records.contains { $0.address == "127.0.0.1" })
    }

    // MARK: Concurrency

    func test_concurrentResolves_deliverExactlyOnce() {
        let total = 60
        let group = DispatchGroup()
        let counters = (0..<total).map { _ in Counter() }
        for index in 0..<total {
            group.enter()
            let host = index.isMultiple(of: 2) ? "127.0.0.1" : "::1"
            DNSResolver.resolve(host, timeout: 3000, queue: queue) { _ in
                counters[index].increment()
                group.leave()
            }
        }
        let exp = expectation(description: "all")
        group.notify(queue: queue) { exp.fulfill() }
        wait(for: [exp], timeout: 10)
        // let any stray double-callbacks land
        let settle = expectation(description: "settle")
        queue.asyncAfter(deadline: .now() + .milliseconds(50)) { settle.fulfill() }
        wait(for: [settle], timeout: 1)
        for counter in counters {
            XCTAssertEqual(counter.value, 1)
        }
    }
}

/// Minimal thread-safe counter for delivery assertions.
private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }

    func increment() {
        lock.lock()
        _value += 1
        lock.unlock()
    }
}
