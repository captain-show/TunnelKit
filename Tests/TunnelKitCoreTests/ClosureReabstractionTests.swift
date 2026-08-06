//
//  ClosureReabstractionTests.swift
//  TunnelKitCoreTests
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

import XCTest

/// Guards the invariant behind `NETunnelInterface.ReadHandlerBox`.
///
/// A GENERIC box stores a function in Swift's maximally abstract convention, so
/// every box/unbox round trip inserts a pair of reabstraction thunks. A read loop
/// that re-boxes its handler once per iteration therefore grows the handler by two
/// permanent stack frames per iteration. In the packet tunnel that meant every
/// batch read from the utun made the handler deeper, until a saturated tunnel
/// walked off the 512 KB GCD worker stack — crashing in whichever function next
/// touched a fresh stack page, far away from the actual defect.
///
/// A CONCRETE stored function type needs no reabstraction, so passing the box
/// along keeps the depth flat.
final class ClosureReabstractionTests: XCTestCase {

    private final class GenericBox<Value>: @unchecked Sendable {
        let value: Value

        init(_ value: Value) {
            self.value = value
        }
    }

    private final class ConcreteBox: @unchecked Sendable {
        let call: () -> Int

        init(_ call: @escaping () -> Int) {
            self.call = call
        }
    }

    /// Returns how deep the stack is, in bytes below this thread's stack top.
    private func stackDepth() -> Int {
        var probe = 0
        return withUnsafeMutablePointer(to: &probe) { pointer in
            let top = pthread_get_stackaddr_np(pthread_self())
            return UInt(bitPattern: top) - UInt(bitPattern: pointer) > 0
                ? Int(UInt(bitPattern: top) - UInt(bitPattern: pointer))
                : 0
        }
    }

    func test_givenGenericBoxReboxedEveryIteration_thenHandlerDepthGrows() {
        var handler: () -> Int = { [unowned self] in self.stackDepth() }

        var depths: [Int] = []
        for _ in 0..<200 {
            // exactly the old shape: unwrap out of a generic box, and let the next
            // iteration wrap that already-thunked closure again
            let boxed = GenericBox(handler)
            handler = boxed.value
            depths.append(handler())
        }

        // Each round trip adds thunk frames, so the probe runs progressively
        // deeper. This is the defect the production fix removes; if a future
        // toolchain stops reabstracting here the assertion goes quiet, which is
        // fine — the fix is correct either way.
        XCTAssertGreaterThan(
            depths.last!, depths.first!,
            "re-boxing through a generic box must be shown to deepen the closure"
        )
        XCTAssertGreaterThan(
            depths.last! - depths.first!, 200,
            "growth must scale with the number of re-boxings"
        )
    }

    func test_givenConcreteBoxPassedAlong_thenHandlerDepthStaysFlat() {
        let probe: () -> Int = { [unowned self] in self.stackDepth() }
        let box = ConcreteBox(probe)

        var depths: [Int] = []
        for _ in 0..<200 {
            // the fixed shape: the SAME box travels through the loop, so the
            // closure is never re-wrapped
            depths.append(box.call())
        }

        let spread = depths.max()! - depths.min()!
        XCTAssertLessThan(
            spread, 512,
            "passing the box along must keep the handler at a constant depth"
        )
    }
}
