//
//  ConnectionStateMachine.swift
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

/// A monotonically increasing token identifying one connection attempt.
///
/// Callbacks scheduled during attempt N carry its token; when they finally
/// run, the state machine rejects them if a newer attempt has started, which
/// makes late callbacks from a defunct attempt harmless by construction.
public typealias ConnectionAttemptToken = UInt64

/// A thread-safe, deterministic state machine for a VPN connection lifecycle.
///
/// All mutations are serialized behind a lock; transition legality is defined
/// by `ConnectionState.allowedNextStates`. Illegal or stale transitions are
/// rejected (never trapped), so racing callbacks cannot corrupt the state.
public final class ConnectionStateMachine: @unchecked Sendable {

    /// A concurrency-safe observer called after an accepted transition.
    public typealias TransitionObserver = @Sendable (
        _ from: ConnectionState,
        _ to: ConnectionState,
        _ attempt: ConnectionAttemptToken
    ) -> Void

    /// The result of a requested transition.
    public enum TransitionResult: Equatable, Sendable {

        /// The transition was applied.
        case accepted(from: ConnectionState)

        /// The transition is illegal from the current state and was ignored.
        case rejectedIllegal(current: ConnectionState)

        /// The transition carried a stale attempt token and was ignored.
        case rejectedStale(currentAttempt: ConnectionAttemptToken)

        /// `true` if the transition was applied.
        public var isAccepted: Bool {
            if case .accepted = self {
                return true
            }
            return false
        }
    }

    private struct Storage {
        var state: ConnectionState

        var attempt: ConnectionAttemptToken

        var observer: TransitionObserver?
    }

    private let storage: OSAllocatedUnfairLock<Storage>

    /// Called after every accepted transition, outside of the internal lock.
    public var onTransition: TransitionObserver? {
        get {
            storage.withLock { $0.observer }
        }
        set {
            storage.withLock { $0.observer = newValue }
        }
    }

    /// Creates a state machine in a terminal state.
    ///
    /// Active initial values are normalized to `.idle`; callers must start an
    /// attempt and traverse the validated lifecycle instead of restoring a
    /// potentially unproven active state.
    public init(initialState: ConnectionState = .idle) {
        let safeInitialState: ConnectionState
        switch initialState {
        case .idle, .disconnected, .failed:
            safeInitialState = initialState

        case .preparing, .connecting, .negotiating, .validating, .connected, .disconnecting:
            safeInitialState = .idle
        }
        storage = OSAllocatedUnfairLock(initialState: Storage(state: safeInitialState, attempt: 0, observer: nil))
    }

    /// The current state.
    public var state: ConnectionState {
        storage.withLock { $0.state }
    }

    /// The token of the current (most recent) attempt.
    public var currentAttempt: ConnectionAttemptToken {
        storage.withLock { $0.attempt }
    }

    /**
     Starts a new connection attempt.

     Invalidates all outstanding tokens and returns a fresh one. The state is
     not changed by this call; follow up with `transition(to: .preparing)` or
     similar.

     - Returns: The token identifying the new attempt.
     */
    @discardableResult
    public func beginAttempt() -> ConnectionAttemptToken {
        storage.withLock {
            Self.incrementAttempt(&$0.attempt)
            return $0.attempt
        }
    }

    /**
     Atomically starts a new attempt AND forces the state to `initialState`,
     regardless of the current state.

     A fresh `startTunnel` must be able to begin even if the previous attempt
     left the machine in a terminal-but-not-`disconnected` state (e.g. a
     forced stop that stalled in `.disconnecting`). Because the token is bumped
     in the same critical section, any late callback from the previous attempt
     is still rejected.

     - Parameter initialState: `.preparing` or `.connecting`. Other values are
       normalized to `.preparing`, so this reset cannot bypass validation.
     - Returns: The token identifying the new attempt.
     */
    @discardableResult
    public func startNewAttempt(initialState: ConnectionState = .preparing) -> ConnectionAttemptToken {
        let safeInitialState: ConnectionState
        switch initialState {
        case .preparing, .connecting:
            safeInitialState = initialState

        default:
            safeInitialState = .preparing
        }
        let (from, attempt, observer): (ConnectionState, ConnectionAttemptToken, TransitionObserver?) = storage.withLock {
            Self.incrementAttempt(&$0.attempt)
            let from = $0.state
            $0.state = safeInitialState
            return (from, $0.attempt, $0.observer)
        }
        if from != safeInitialState {
            observer?(from, safeInitialState, attempt)
        }
        return attempt
    }

    /**
     Requests a transition to `newState`.

     - Parameter newState: The target state.
     - Parameter attempt: When non-nil, the transition is only applied if the
       token matches the current attempt. Pass the token captured when the
       triggering work was scheduled to neutralize late callbacks.
     - Returns: The outcome; rejected transitions leave the state untouched.
     */
    @discardableResult
    public func transition(to newState: ConnectionState, attempt: ConnectionAttemptToken? = nil) -> TransitionResult {
        // capture the accepted token inside the lock and return it alongside
        // the result, so onTransition reports a consistent snapshot instead of
        // a re-read a concurrent beginAttempt() could have advanced
        let (result, acceptedAttempt, observer): (TransitionResult, ConnectionAttemptToken, TransitionObserver?) = storage.withLock {
            if let attempt, attempt != $0.attempt {
                return (.rejectedStale(currentAttempt: $0.attempt), $0.attempt, nil)
            }
            guard $0.state.canTransition(to: newState) else {
                return (.rejectedIllegal(current: $0.state), $0.attempt, nil)
            }
            let from = $0.state
            $0.state = newState
            return (.accepted(from: from), $0.attempt, $0.observer)
        }
        if case .accepted(let from) = result {
            observer?(from, newState, acceptedAttempt)
        }
        return result
    }

    /**
     Verifies that `attempt` is still the current one.

     - Parameter attempt: The token to check.
     - Returns: `true` if no newer attempt has started.
     */
    public func isCurrent(_ attempt: ConnectionAttemptToken) -> Bool {
        storage.withLock { $0.attempt == attempt }
    }

    /**
     Atomically reads the state and attempt token together.
     */
    public func snapshot() -> (state: ConnectionState, attempt: ConnectionAttemptToken) {
        storage.withLock { ($0.state, $0.attempt) }
    }

    private static func incrementAttempt(_ attempt: inout ConnectionAttemptToken) {
        attempt &+= 1
        if attempt == 0 {
            attempt = 1
        }
    }
}
