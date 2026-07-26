//
//  DNSResolver.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 12/15/17.
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
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

import Foundation
import dnssd

/// Result of `DNSResolver`.
public struct DNSRecord: Equatable, Sendable {

    /// Address string.
    public let address: String

    /// `true` if IPv6.
    public let isIPv6: Bool

    public init(address: String, isIPv6: Bool) {
        self.address = address
        self.isIPv6 = isIPv6
    }
}

/// The address family a caller can actually use.
///
/// `dns_sd` streams A and AAAA records in independent callback batches, so the
/// resolver must decide when a partial result is complete enough to deliver.
/// A family-specific caller (e.g. a `UDP6`/`TCP4` transport) passes its family
/// so the resolver waits for a usable record instead of settling early on the
/// other family and reporting a spurious failure.
public enum DNSAddressFamily: Sendable {

    /// Either family is acceptable (the default).
    case any

    /// Only IPv4 records are usable by the caller.
    case ipv4

    /// Only IPv6 records are usable by the caller.
    case ipv6
}

/// Errors coming from `DNSResolver`.
public enum DNSError: Error, Hashable, Sendable {

    /// The hostname is empty or too long for DNS.
    case invalidHostname

    /// The timeout is outside the supported range.
    case invalidTimeout

    /// Resolution failed.
    case failure

    /// Resolution timed out.
    case timeout

    /// The DNS-SD daemon returned a specific error code.
    case service(code: Int32)
}

extension DNSError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidHostname:
            return "The DNS hostname is empty or too long."

        case .invalidTimeout:
            return "The DNS timeout must be between 0 and 86400000 milliseconds."

        case .failure:
            return "DNS resolution failed."

        case .timeout:
            return "DNS resolution timed out."

        case .service(let code):
            return "DNS-SD resolution failed with error code \(code)."
        }
    }
}

/// Convenient methods for DNS resolution.
///
/// Resolution is performed with the asynchronous `DNSServiceGetAddrInfo` API
/// from `dns_sd`. Unlike a blocking `getaddrinfo` call, this uses event-driven
/// socket I/O delivered on a dispatch queue: no worker thread is ever parked
/// waiting for a reply, so a timeout or cancellation frees the resolver
/// immediately and can never exhaust a thread pool. Both IPv4 and IPv6 records
/// are requested in a single query.
public final class DNSResolver {

    /// A single serial queue drives every in-flight `dns_sd` query. Because the
    /// API is event-driven (never blocks), one queue is enough regardless of
    /// how many resolutions run concurrently, which bounds resource usage to a
    /// single thread and makes thread-pool exhaustion structurally impossible.
    private static let callbackQueue = DispatchQueue(label: "com.algoritmico.TunnelKit.DNSResolver")

    /**
     Resolves a hostname asynchronously.

     The completion handler is guaranteed to be called exactly once, on
     `queue`, either with the records, a failure, or a timeout.

     - Parameter hostname: The hostname to resolve.
     - Parameter timeout: The timeout in milliseconds.
     - Parameter queue: The queue to execute the `completionHandler` in.
     - Parameter family: The address family the caller can use. When it is not
       `.any`, the resolver waits for a usable record instead of settling early
       on the other family.
     - Parameter completionHandler: The completion handler with the resolved addresses and an optional error.
     */
    public static func resolve(_ hostname: String, timeout: Int, queue: DispatchQueue, family: DNSAddressFamily = .any, completionHandler: @escaping (Result<[DNSRecord], Error>) -> Void) {
        let completion = UncheckedSendableCallback(completionHandler)
        if let inputError = inputError(hostname: hostname, timeout: timeout) {
            queue.async {
                completion.callback(.failure(inputError))
            }
            return
        }
        // A numeric literal needs no network lookup; resolve it locally and
        // synchronously (delivered on `queue` to keep the async contract).
        if let literal = numericRecord(for: hostname) {
            queue.async {
                completion.callback(.success([literal]))
            }
            return
        }
        let query = Query(hostname: hostname, callbackQueue: callbackQueue, requiredFamily: family)
        query.start(timeout: timeout) { result in
            queue.async {
                completion.callback(result)
            }
        }
    }

    /**
     Resolves a hostname, honoring structured-concurrency cancellation.

     Cancelling the surrounding `Task` tears the query down immediately (the
     underlying `dns_sd` service ref is deallocated) and throws
     `CancellationError`.

     - Parameter hostname: The hostname to resolve.
     - Parameter timeout: The timeout in milliseconds.
     - Parameter family: The address family the caller can use. When it is not
       `.any`, the resolver waits for a usable record instead of settling early
       on the other family.
     - Returns: The resolved records.
     - Throws: `TunnelKitCoreError.dnsResolver` on failure/timeout, `CancellationError` on cancellation.
     */
    public static func resolve(_ hostname: String, timeout: Int, family: DNSAddressFamily = .any) async throws -> [DNSRecord] {
        try Task.checkCancellation()
        if let inputError = inputError(hostname: hostname, timeout: timeout) {
            throw inputError
        }
        if let literal = numericRecord(for: hostname) {
            return [literal]
        }
        let query = Query(hostname: hostname, callbackQueue: callbackQueue, requiredFamily: family)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                query.start(timeout: timeout) { result in
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            query.cancel()
        }
    }

    /// Returns a record for a numeric IPv4/IPv6 literal, or nil if `hostname`
    /// is not a numeric address. No network lookup is performed.
    private static func numericRecord(for hostname: String) -> DNSRecord? {
        var addr4 = in_addr()
        if hostname.withCString({ inet_pton(AF_INET, $0, &addr4) }) == 1 {
            return DNSRecord(address: hostname, isIPv6: false)
        }
        var addr6 = in6_addr()
        if hostname.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 {
            return DNSRecord(address: hostname, isIPv6: true)
        }
        return nil
    }

    private static func inputError(hostname: String, timeout: Int) -> TunnelKitCoreError? {
        let trimmedHostname = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedHostname.isEmpty,
              trimmedHostname == hostname,
              hostname.utf8.count <= 253 else {
            return .dnsResolver(.invalidHostname)
        }
        guard (0...86_400_000).contains(timeout) else {
            return .dnsResolver(.invalidTimeout)
        }
        return nil
    }

    /**
     Returns a `String` representation from a numeric IPv4 address.

     - Parameter ipv4: The IPv4 address as a 32-bit number.
     - Returns: The string representation of `ipv4`.
     */
    public static func string(fromIPv4 ipv4: UInt32) -> String {
        var remainder = ipv4
        var groups: [UInt32] = []
        var base: UInt32 = 1 << 24
        while base > 0 {
            groups.append(remainder / base)
            remainder %= base
            base >>= 8
        }
        return groups.map { "\($0)" }.joined(separator: ".")
    }

    /**
     Returns a numeric representation from an IPv4 address.

     - Parameter string: The IPv4 address as a string.
     - Returns: The numeric representation of `string`.
     */
    public static func ipv4(fromString string: String) -> UInt32? {
        var addr = in_addr()
        let result = string.withCString {
            inet_pton(AF_INET, $0, &addr)
        }
        guard result > 0 else {
            return nil
        }
        return CFSwapInt32BigToHost(addr.s_addr)
    }

    private init() {
    }
}

/// Bridges callback-based public APIs that predate Swift concurrency. The
/// callback is invoked only on the queue documented by the API.
private final class UncheckedSendableCallback<Callback>: @unchecked Sendable {
    let callback: Callback

    init(_ callback: Callback) {
        self.callback = callback
    }
}

// MARK: - Query

/// Pure callback-batch accumulator, kept internal for deterministic tests.
struct DNSReplyAccumulator {
    enum Action: Equatable {
        case wait

        case settle

        case fail(DNSError)
    }

    private(set) var records: [DNSRecord] = []

    mutating func consume(
        flags: DNSServiceFlags,
        errorCode: DNSServiceErrorType,
        record: DNSRecord?
    ) -> Action {
        guard errorCode == kDNSServiceErr_NoError else {
            return .fail(errorCode == kDNSServiceErr_Timeout ? .timeout : .service(code: errorCode))
        }
        if let record {
            let isAddition = (flags & DNSServiceFlags(kDNSServiceFlagsAdd)) != 0
            if isAddition {
                if !records.contains(record) {
                    records.append(record)
                }
            } else {
                records.removeAll { $0 == record }
            }
        }
        let moreComing = (flags & DNSServiceFlags(kDNSServiceFlagsMoreComing)) != 0
        return moreComing ? .wait : .settle
    }
}

/// Invalidates superseded A/AAAA settlement timers deterministically.
///
/// `DispatchWorkItem.cancel()` only marks an item as cancelled; a queued item
/// may still execute. A generation therefore guards delivery in addition to
/// cancellation, and an empty record set always invalidates the prior timer.
struct DNSSettlementTracker {
    enum Action: Equatable {
        case wait

        case finish

        case schedule(generation: UInt64)
    }

    private(set) var generation: UInt64 = 0

    let requiredFamily: DNSAddressFamily

    init(requiredFamily: DNSAddressFamily = .any) {
        self.requiredFamily = requiredFamily
    }

    mutating func update(records: [DNSRecord]) -> Action {
        generation &+= 1
        guard !records.isEmpty else {
            return .wait
        }

        let hasIPv4 = records.contains { !$0.isIPv6 }
        let hasIPv6 = records.contains { $0.isIPv6 }
        switch requiredFamily {
        case .ipv4:
            // The caller can only use IPv4. Deliver as soon as an A record
            // appears; otherwise keep waiting (up to the operation timeout)
            // rather than settling on unusable IPv6-only records.
            return hasIPv4 ? .finish : .wait

        case .ipv6:
            return hasIPv6 ? .finish : .wait

        case .any:
            // Either family is usable: finish once both are in, otherwise give
            // the second family a brief grace period before settling on one.
            if hasIPv4 && hasIPv6 {
                return .finish
            }
            return .schedule(generation: generation)
        }
    }

    func canFinish(generation scheduledGeneration: UInt64, records: [DNSRecord]) -> Bool {
        scheduledGeneration == generation && !records.isEmpty
    }

    mutating func invalidate() {
        generation &+= 1
    }
}

/// One `DNSServiceGetAddrInfo` resolution.
///
/// Thread-safety / `@unchecked Sendable` justification:
/// every stored property is read and written ONLY on `callbackQueue`. The
/// `dns_sd` reply is delivered on that queue (via `DNSServiceSetDispatchQueue`),
/// the timeout work item is scheduled on it, `start` bootstraps on it, and
/// `cancel` hops onto it. There is no other executor that touches this object's
/// state, so the confinement is total and no lock is needed. This invariant is
/// exercised by `DNSResolverTests.test_concurrentResolves_deliverExactlyOnce`.
private final class Query: @unchecked Sendable {
    private static let singleFamilyGrace: DispatchTimeInterval = .milliseconds(250)

    private let hostname: String

    private let callbackQueue: DispatchQueue

    // MARK: State confined to `callbackQueue`

    private var deliver: (@Sendable (Result<[DNSRecord], Error>) -> Void)?

    private var serviceRef: DNSServiceRef?

    private var accumulator = DNSReplyAccumulator()

    private var timeoutItem: DispatchWorkItem?

    /// Briefly coalesces independently delivered A and AAAA callbacks.
    private var settlementItem: DispatchWorkItem?

    private var settlementTracker: DNSSettlementTracker

    /// Set if `cancel()` ran before `start()` had a chance to set up, so the
    /// setup can bail out instead of issuing a doomed lookup.
    private var pendingCancel = false

    /// Keeps the query alive for the duration of the resolution. Cleared on
    /// finish, which is the sole ownership anchor.
    private var selfRetain: Query?

    init(hostname: String, callbackQueue: DispatchQueue, requiredFamily: DNSAddressFamily = .any) {
        self.hostname = hostname
        self.callbackQueue = callbackQueue
        settlementTracker = DNSSettlementTracker(requiredFamily: requiredFamily)
    }

    func start(timeout: Int, completion: @escaping @Sendable (Result<[DNSRecord], Error>) -> Void) {
        callbackQueue.async {
            self.selfRetain = self
            self.deliver = completion

            // a cancel that raced ahead of this setup block wins immediately
            guard !self.pendingCancel else {
                self.finish(.failure(CancellationError()))
                return
            }

            var ref: DNSServiceRef?
            let context = Unmanaged.passUnretained(self).toOpaque()
            let proto = UInt32(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6)
            let error = DNSServiceGetAddrInfo(
                &ref,
                0,
                0,
                proto,
                self.hostname,
                dnsServiceAddrInfoReply,
                context
            )
            guard error == kDNSServiceErr_NoError, let ref else {
                self.finish(.failure(TunnelKitCoreError.dnsResolver(.service(code: error))))
                return
            }
            self.serviceRef = ref
            let schedulingError = DNSServiceSetDispatchQueue(ref, self.callbackQueue)
            guard schedulingError == kDNSServiceErr_NoError else {
                self.finish(.failure(TunnelKitCoreError.dnsResolver(.service(code: schedulingError))))
                return
            }

            let item = DispatchWorkItem {
                self.finishAtTimeout()
            }
            self.timeoutItem = item
            self.callbackQueue.asyncAfter(deadline: .now() + .milliseconds(timeout), execute: item)
        }
    }

    func cancel() {
        callbackQueue.async {
            // if start() has not run yet, remember the intent so it aborts;
            // otherwise finish now (no-op if already finished)
            self.pendingCancel = true
            if self.deliver != nil {
                self.finish(.failure(CancellationError()))
            }
        }
    }

    // MARK: Callback-queue only

    fileprivate func handleReply(flags: DNSServiceFlags, errorCode: DNSServiceErrorType, address: UnsafePointer<sockaddr>?) {
        guard deliver != nil else {
            return
        }
        let record = address.flatMap(Query.record(from:))
        switch accumulator.consume(flags: flags, errorCode: errorCode, record: record) {
        case .wait:
            // A callback batch is still changing. Any prior quiet-period timer
            // now describes stale records and must not be allowed to finish.
            invalidateSettlement()

        case .settle:
            scheduleSettlement()

        case .fail(let error):
            if error == .timeout, !accumulator.records.isEmpty {
                finish(.success(accumulator.records))
            } else {
                finish(.failure(TunnelKitCoreError.dnsResolver(error)))
            }
        }
    }

    /// A and AAAA results are allowed to arrive in separate callback batches.
    /// A short, resettable grace period collects the second address family.
    /// Empty batches remain open until a later record or the operation timeout.
    private func scheduleSettlement() {
        settlementItem?.cancel()
        settlementItem = nil

        // An empty callback is not terminal. DNS-SD may deliver it before a
        // later A/AAAA callback, so the operation-wide timeout remains the
        // only authority that can fail an empty result.
        switch settlementTracker.update(records: accumulator.records) {
        case .wait:
            return

        case .finish:
            finish(.success(accumulator.records))
            return

        case .schedule(let generation):
            let item = DispatchWorkItem { [weak self] in
                guard let self,
                      self.settlementTracker.canFinish(
                        generation: generation,
                        records: self.accumulator.records
                      ) else {
                    return
                }
                self.settlementItem = nil
                self.finish(.success(self.accumulator.records))
            }
            settlementItem = item
            callbackQueue.asyncAfter(deadline: .now() + Self.singleFamilyGrace, execute: item)
        }
    }

    private func invalidateSettlement() {
        settlementTracker.invalidate()
        settlementItem?.cancel()
        settlementItem = nil
    }

    private func finishAtTimeout() {
        if accumulator.records.isEmpty {
            finish(.failure(TunnelKitCoreError.dnsResolver(.timeout)))
        } else {
            finish(.success(accumulator.records))
        }
    }

    private func finish(_ result: Result<[DNSRecord], Error>) {
        guard let deliver else {
            return
        }
        self.deliver = nil
        timeoutItem?.cancel()
        timeoutItem = nil
        invalidateSettlement()
        if let serviceRef {
            DNSServiceRefDeallocate(serviceRef)
        }
        serviceRef = nil
        deliver(result)
        // release the ownership anchor last, so nothing runs after delivery
        selfRetain = nil
    }

    private static func record(from address: UnsafePointer<sockaddr>) -> DNSRecord? {
        let family = address.pointee.sa_family
        guard family == sa_family_t(AF_INET) || family == sa_family_t(AF_INET6) else {
            return nil
        }
        let isIPv6 = family == sa_family_t(AF_INET6)
        let length = socklen_t(isIPv6 ? MemoryLayout<sockaddr_in6>.size : MemoryLayout<sockaddr_in>.size)
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        // NI_NUMERICHOST only formats an already-resolved address; it performs
        // no network lookup and never blocks.
        let result = getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
        guard result == 0 else {
            return nil
        }
        // host is a NUL-terminated C string; drop the terminator before decoding
        let address = host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return DNSRecord(address: String(decoding: address, as: UTF8.self), isIPv6: isIPv6)
    }
}

/// Free function so it can be passed as a C function pointer (no captures).
private func dnsServiceAddrInfoReply(
    _ sdRef: DNSServiceRef?,
    _ flags: DNSServiceFlags,
    _ interfaceIndex: UInt32,
    _ errorCode: DNSServiceErrorType,
    _ hostname: UnsafePointer<CChar>?,
    _ address: UnsafePointer<sockaddr>?,
    _ ttl: UInt32,
    _ context: UnsafeMutableRawPointer?
) {
    guard let context else {
        return
    }
    let query = Unmanaged<Query>.fromOpaque(context).takeUnretainedValue()
    query.handleReply(flags: flags, errorCode: errorCode, address: address)
}
