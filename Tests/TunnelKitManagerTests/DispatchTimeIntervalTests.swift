//
//  DispatchTimeIntervalTests.swift
//  TunnelKitManagerTests
//
//  Copyright (c) 2026 Davide De Rosa. All rights reserved.
//

import Dispatch
import Testing
@testable import TunnelKitManager

@Suite("DispatchTimeInterval conversion")
struct DispatchTimeIntervalTests {
    @Test("Nanosecond conversion clamps invalid and overflowing values")
    func saturatedNanoseconds() {
        #expect(DispatchTimeInterval.seconds(-1).nanoseconds == 0)
        #expect(DispatchTimeInterval.nanoseconds(-1).nanoseconds == 0)
        #expect(DispatchTimeInterval.milliseconds(2).nanoseconds == 2_000_000)
        #expect(DispatchTimeInterval.seconds(Int.max).nanoseconds == .max)
    }
}
