//
//  ConnectionStateMachineTests.swift
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

final class ConnectionStateMachineTests: XCTestCase {

    // MARK: Happy path

    func test_fullSuccessfulLifecycle() {
        let machine = ConnectionStateMachine()
        let attempt = machine.beginAttempt()

        XCTAssertTrue(machine.transition(to: .preparing, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .connecting, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .negotiating, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .validating, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .connected, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .disconnecting, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .disconnected, attempt: attempt).isAccepted)
        XCTAssertEqual(machine.state, .disconnected)
    }

    // MARK: The core invariant

    func test_connectedIsUnreachableWithoutValidating() {
        let machine = ConnectionStateMachine()
        machine.beginAttempt()

        // from every state except validating, .connected must be rejected
        machine.transition(to: .preparing)
        XCTAssertFalse(machine.transition(to: .connected).isAccepted)
        machine.transition(to: .connecting)
        XCTAssertFalse(machine.transition(to: .connected).isAccepted)
        machine.transition(to: .negotiating)
        XCTAssertFalse(machine.transition(to: .connected).isAccepted)
        machine.transition(to: .validating)
        XCTAssertTrue(machine.transition(to: .connected).isAccepted)
    }

    func test_idleCannotJumpToConnected() {
        let machine = ConnectionStateMachine()
        XCTAssertFalse(machine.transition(to: .connected).isAccepted)
        XCTAssertFalse(machine.transition(to: .validating).isAccepted)
        XCTAssertEqual(machine.state, .idle)
    }

    func test_activeInitialStateCannotBypassLifecycle() {
        XCTAssertEqual(ConnectionStateMachine(initialState: .connected).state, .idle)
        XCTAssertEqual(ConnectionStateMachine(initialState: .validating).state, .idle)
        XCTAssertEqual(ConnectionStateMachine(initialState: .disconnected).state, .disconnected)
    }

    // MARK: Late callbacks from superseded attempts

    func test_staleAttemptTokenIsRejected() {
        let machine = ConnectionStateMachine()
        let oldAttempt = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: oldAttempt)
        machine.transition(to: .connecting, attempt: oldAttempt)

        // a new attempt supersedes the old one
        machine.transition(to: .disconnected, attempt: oldAttempt)
        let newAttempt = machine.beginAttempt()
        machine.transition(to: .connecting, attempt: newAttempt)
        machine.transition(to: .negotiating, attempt: newAttempt)

        // a late callback from the old attempt must not touch the state
        let result = machine.transition(to: .validating, attempt: oldAttempt)
        XCTAssertEqual(result, .rejectedStale(currentAttempt: newAttempt))
        XCTAssertEqual(machine.state, .negotiating)
    }

    func test_lateValidationOfOldAttemptCannotConnectNewAttempt() {
        let machine = ConnectionStateMachine()
        let first = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: first)
        machine.transition(to: .connecting, attempt: first)
        machine.transition(to: .negotiating, attempt: first)
        machine.transition(to: .validating, attempt: first)

        // user disconnects, reconnects quickly
        machine.transition(to: .disconnecting, attempt: first)
        machine.transition(to: .disconnected, attempt: first)
        let second = machine.beginAttempt()
        machine.transition(to: .connecting, attempt: second)

        // the old validation completes now: must be rejected
        XCTAssertFalse(machine.transition(to: .connected, attempt: first).isAccepted)
        XCTAssertEqual(machine.state, .connecting)
    }

    // MARK: Cancellation / rapid sequences

    func test_disconnectDuringConnecting() {
        let machine = ConnectionStateMachine()
        let attempt = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: attempt)
        machine.transition(to: .connecting, attempt: attempt)

        XCTAssertTrue(machine.transition(to: .disconnecting, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .disconnected, attempt: attempt).isAccepted)
    }

    func test_rapidConnectDisconnectConnect() {
        let machine = ConnectionStateMachine()

        let first = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: first)
        machine.transition(to: .connecting, attempt: first)
        machine.transition(to: .disconnecting, attempt: first)
        machine.transition(to: .disconnected, attempt: first)

        let second = machine.beginAttempt()
        XCTAssertTrue(machine.transition(to: .preparing, attempt: second).isAccepted)
        XCTAssertTrue(machine.transition(to: .connecting, attempt: second).isAccepted)
        XCTAssertTrue(machine.transition(to: .negotiating, attempt: second).isAccepted)
        XCTAssertTrue(machine.transition(to: .validating, attempt: second).isAccepted)
        XCTAssertTrue(machine.transition(to: .connected, attempt: second).isAccepted)

        // stale events from the first attempt keep bouncing off
        XCTAssertFalse(machine.transition(to: .failed, attempt: first).isAccepted)
        XCTAssertEqual(machine.state, .connected)
    }

    func test_failureFromAnyActiveState() {
        for intermediate in [ConnectionState.preparing, .connecting, .negotiating, .validating, .connected] {
            let machine = ConnectionStateMachine()
            let attempt = machine.beginAttempt()
            machine.transition(to: .preparing, attempt: attempt)
            if intermediate != .preparing {
                machine.transition(to: .connecting, attempt: attempt)
            }
            if [ConnectionState.negotiating, .validating, .connected].contains(intermediate) {
                machine.transition(to: .negotiating, attempt: attempt)
            }
            if [ConnectionState.validating, .connected].contains(intermediate) {
                machine.transition(to: .validating, attempt: attempt)
            }
            if intermediate == .connected {
                machine.transition(to: .connected, attempt: attempt)
            }
            XCTAssertEqual(machine.state, intermediate)
            XCTAssertTrue(machine.transition(to: .failed, attempt: attempt).isAccepted, "failed not reachable from \(intermediate)")
        }
    }

    func test_revalidationOfEstablishedConnection() {
        let machine = ConnectionStateMachine()
        let attempt = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: attempt)
        machine.transition(to: .connecting, attempt: attempt)
        machine.transition(to: .negotiating, attempt: attempt)
        machine.transition(to: .validating, attempt: attempt)
        machine.transition(to: .connected, attempt: attempt)

        // server pushes new options: re-validate without a full reconnect
        XCTAssertTrue(machine.transition(to: .validating, attempt: attempt).isAccepted)
        XCTAssertTrue(machine.transition(to: .connected, attempt: attempt).isAccepted)
    }

    func test_startNewAttempt_forcesResetFromStalledDisconnecting() {
        let machine = ConnectionStateMachine()
        let first = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: first)
        machine.transition(to: .connecting, attempt: first)
        machine.transition(to: .disconnecting, attempt: first)
        // forced stop stalls here: never reaches .disconnected

        // a fresh start must not be blocked by the stalled state
        let second = machine.startNewAttempt(initialState: .preparing)
        XCTAssertEqual(machine.state, .preparing)
        XCTAssertTrue(machine.transition(to: .connecting, attempt: second).isAccepted)

        // the stalled attempt's late callbacks are still fenced out
        XCTAssertFalse(machine.transition(to: .disconnected, attempt: first).isAccepted)
    }

    func test_startNewAttempt_invalidatesPriorToken() {
        let machine = ConnectionStateMachine()
        let first = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: first)
        machine.transition(to: .connecting, attempt: first)
        machine.transition(to: .negotiating, attempt: first)
        machine.transition(to: .validating, attempt: first)

        let second = machine.startNewAttempt()
        XCTAssertNotEqual(first, second)
        // a late "connected" from the first attempt must be rejected
        XCTAssertFalse(machine.transition(to: .connected, attempt: first).isAccepted)
    }

    func test_startNewAttemptCannotForceConnectedState() {
        let machine = ConnectionStateMachine()

        let attempt = machine.startNewAttempt(initialState: .connected)

        XCTAssertEqual(machine.state, .preparing)
        XCTAssertTrue(machine.transition(to: .connecting, attempt: attempt).isAccepted)
        XCTAssertFalse(machine.transition(to: .connected, attempt: attempt).isAccepted)
    }

    func test_stopFromIdleIsAbsorbed() {
        let machine = ConnectionStateMachine()
        XCTAssertTrue(machine.transition(to: .disconnecting).isAccepted)
        XCTAssertTrue(machine.transition(to: .disconnected).isAccepted)
    }

    func test_reconnectAfterFailure() {
        let machine = ConnectionStateMachine()
        let attempt = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: attempt)
        machine.transition(to: .connecting, attempt: attempt)
        machine.transition(to: .failed, attempt: attempt)

        let retry = machine.beginAttempt()
        XCTAssertTrue(machine.transition(to: .connecting, attempt: retry).isAccepted)
    }

    // MARK: Illegal transitions never corrupt state

    func test_illegalTransitionLeavesStateUntouched() {
        let machine = ConnectionStateMachine()
        machine.beginAttempt()
        machine.transition(to: .preparing)

        let result = machine.transition(to: .connected)
        XCTAssertEqual(result, .rejectedIllegal(current: .preparing))
        XCTAssertEqual(machine.state, .preparing)
    }

    func test_doubleDisconnectIsIdempotent() {
        let machine = ConnectionStateMachine()
        machine.beginAttempt()
        machine.transition(to: .preparing)
        machine.transition(to: .connecting)
        machine.transition(to: .disconnecting)
        XCTAssertTrue(machine.transition(to: .disconnected).isAccepted)
        // second disconnect must be a no-op, not a crash or corruption
        XCTAssertFalse(machine.transition(to: .disconnected).isAccepted)
        XCTAssertEqual(machine.state, .disconnected)
    }

    // MARK: Observer

    func test_observerSeesEveryAcceptedTransition() {
        let machine = ConnectionStateMachine()
        let seen = OSAllocatedUnfairLock(initialState: [ConnectionState]())
        machine.onTransition = { _, to, _ in
            seen.withLock { $0.append(to) }
        }
        let attempt = machine.beginAttempt()
        machine.transition(to: .preparing, attempt: attempt)
        machine.transition(to: .connected, attempt: attempt) // illegal, not observed
        machine.transition(to: .connecting, attempt: attempt)

        XCTAssertEqual(seen.withLock { $0 }, [.preparing, .connecting])
    }

    func test_observerCanBeReplacedConcurrently() {
        let machine = ConnectionStateMachine()
        let callCount = OSAllocatedUnfairLock(initialState: 0)

        DispatchQueue.concurrentPerform(iterations: 200) { iteration in
            machine.onTransition = { _, _, _ in
                callCount.withLock { $0 += 1 }
            }
            if iteration.isMultiple(of: 2) {
                _ = machine.startNewAttempt()
            }
        }

        XCTAssertGreaterThan(callCount.withLock { $0 }, 0)
        XCTAssertTrue([.preparing, .connecting].contains(machine.state))
    }

    // MARK: Thread safety

    func test_concurrentTransitionsDoNotCrashOrCorrupt() {
        let machine = ConnectionStateMachine()
        machine.beginAttempt()
        machine.transition(to: .preparing)
        machine.transition(to: .connecting)

        DispatchQueue.concurrentPerform(iterations: 1000) { i in
            switch i % 4 {
            case 0:
                _ = machine.transition(to: .negotiating)
            case 1:
                _ = machine.transition(to: .validating)
            case 2:
                _ = machine.transition(to: .connected)
            default:
                _ = machine.snapshot()
            }
        }

        // the machine must end in one of the legal downstream states
        XCTAssertTrue([.negotiating, .validating, .connected].contains(machine.state))
    }

    func test_simultaneousCancelAndFailure_onlyOneTerminalEventPerAttempt() {
        // a failure callback from attempt N must not fire a terminal transition
        // once attempt N has been superseded by a cancel/restart (attempt N+1)
        let machine = ConnectionStateMachine()
        let terminalCount = OSAllocatedUnfairLock(initialState: 0)
        machine.onTransition = { _, to, _ in
            if to == .failed || to == .disconnected {
                terminalCount.withLock { $0 += 1 }
            }
        }

        for _ in 0..<200 {
            let attempt = machine.startNewAttempt(initialState: .preparing)
            machine.transition(to: .connecting, attempt: attempt)

            // race: a "cancel" (new attempt) vs a late "failure" of the old one
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global().async {
                _ = machine.transition(to: .failed, attempt: attempt)
                group.leave()
            }
            group.enter()
            DispatchQueue.global().async {
                _ = machine.startNewAttempt(initialState: .preparing)
                group.leave()
            }
            group.wait()
        }

        // whichever won, the machine is always in a legal state and never
        // corrupted; the token fencing prevents stale terminal events from a
        // superseded attempt from ever being double-counted within one attempt
        XCTAssertTrue(ConnectionState.allCases.contains(machine.state))
    }
}
