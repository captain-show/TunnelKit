//
//  TestClock.swift
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

import Foundation
import os

/// A manually driven clock for testing timeouts without real waiting.
final class TestClock: Clock, @unchecked Sendable {
    struct Instant: InstantProtocol {
        var offset: Duration

        func advanced(by duration: Duration) -> Instant {
            Instant(offset: offset + duration)
        }

        func duration(to other: Instant) -> Duration {
            other.offset - offset
        }

        static func < (lhs: Instant, rhs: Instant) -> Bool {
            lhs.offset < rhs.offset
        }
    }

    private struct Sleeper {
        let id: UInt64

        let deadline: Instant

        let continuation: CheckedContinuation<Void, Error>
    }

    private struct State {
        var now = Instant(offset: .zero)

        var sleepers: [Sleeper] = []

        var nextId: UInt64 = 0

        var cancelledIds: Set<UInt64> = []
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    var minimumResolution: Duration {
        .zero
    }

    var now: Instant {
        state.withLock { $0.now }
    }

    func sleep(until deadline: Instant, tolerance: Duration?) async throws {
        let id: UInt64 = state.withLock {
            $0.nextId += 1
            return $0.nextId
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let action: (@Sendable () -> Void)? = state.withLock { state in
                    if state.cancelledIds.remove(id) != nil {
                        return { continuation.resume(throwing: CancellationError()) }
                    }
                    if deadline <= state.now {
                        return { continuation.resume() }
                    }
                    state.sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                    return nil
                }
                action?()
            }
        } onCancel: {
            let sleeper: Sleeper? = state.withLock { state in
                if let index = state.sleepers.firstIndex(where: { $0.id == id }) {
                    return state.sleepers.remove(at: index)
                }
                state.cancelledIds.insert(id)
                return nil
            }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }

    /**
     Advances the clock, resuming every sleeper whose deadline has passed.
     Yields generously so that resumed tasks make progress before returning.
     */
    func advance(by duration: Duration) async {
        await megaYield()
        let due: [Sleeper] = state.withLock { state in
            state.now = state.now.advanced(by: duration)
            let now = state.now
            let expired = state.sleepers.filter { $0.deadline <= now }
            state.sleepers.removeAll { $0.deadline <= now }
            return expired.sorted { $0.deadline < $1.deadline }
        }
        for sleeper in due {
            sleeper.continuation.resume()
        }
        await megaYield()
    }

    /// Cooperatively yields many times so suspended tasks can reach their
    /// next suspension point.
    func megaYield() async {
        for _ in 0..<50 {
            await Task.yield()
        }
    }
}
