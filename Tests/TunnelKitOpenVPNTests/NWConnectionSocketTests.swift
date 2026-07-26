//
//  NWConnectionSocketTests.swift
//  TunnelKitOpenVPNTests
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
import Network
import TunnelKitCore
@testable import TunnelKitAppExtension
@testable import TunnelKitOpenVPNAppExtension
import TunnelKitOpenVPNCore

final class NWConnectionSocketTests: XCTestCase {
    private let queue = DispatchQueue(label: "NWConnectionSocketTests")

    // MARK: TCP

    func test_tcp_connectsAndBecomesActive() throws {
        let server = try EchoServer(isStream: true)
        defer { server.stop() }
        let socket = makeSocket(port: server.port, reliable: true)
        let recorder = DelegateRecorder()
        socket.delegate = recorder

        let active = expectation(description: "active")
        recorder.onActive = { active.fulfill() }
        socket.observe(queue: queue, activeTimeout: 3000)
        wait(for: [active], timeout: 5)

        XCTAssertFalse(socket.isShutdown)
        socket.shutdown()
    }

    func test_tcp_roundTripThroughLink() throws {
        let server = try EchoServer(isStream: true)
        defer { server.stop() }
        let socket = makeSocket(port: server.port, reliable: true)
        let recorder = DelegateRecorder()
        socket.delegate = recorder

        let active = expectation(description: "active")
        recorder.onActive = { active.fulfill() }
        socket.observe(queue: queue, activeTimeout: 3000)
        wait(for: [active], timeout: 5)

        let link = socket.link(userObject: nil)
        let received = expectation(description: "received")
        let payload = Data([0xAA, 0xBB, 0xCC, 0xDD])
        link.setReadHandler(queue: queue) { packets, error in
            XCTAssertNil(error)
            if let packets, packets.contains(payload) {
                received.fulfill()
            }
        }
        link.writePacket(payload, completionHandler: nil)
        wait(for: [received], timeout: 5)
        socket.shutdown()
    }

    func test_tcp_remoteCloseSurfacesError() throws {
        let server = try EchoServer(isStream: true)
        let socket = makeSocket(port: server.port, reliable: true)
        let recorder = DelegateRecorder()
        socket.delegate = recorder
        let active = expectation(description: "active")
        recorder.onActive = { active.fulfill() }
        socket.observe(queue: queue, activeTimeout: 3000)
        wait(for: [active], timeout: 5)

        let link = socket.link(userObject: nil)
        let payload = Data([0x11, 0x22, 0x33])
        let echoed = expectation(description: "echoed")
        let gotError = expectation(description: "eof")
        let sawEcho = Locked(false)
        link.setReadHandler(queue: queue) { packets, error in
            if let packets, packets.contains(payload), !sawEcho.value {
                sawEcho.mutate { $0 = true }
                echoed.fulfill()
            }
            if error != nil {
                gotError.fulfill()
            }
        }
        // establish real traffic first, so the server side is fully accepted
        link.writePacket(payload, completionHandler: nil)
        wait(for: [echoed], timeout: 5)

        // peer closes the stream (FIN): must surface as a read error
        server.closeConnections()
        wait(for: [gotError], timeout: 5)
        server.stop()
        socket.shutdown()
    }

    // MARK: UDP

    func test_udp_roundTripThroughLink() throws {
        let server = try EchoServer(isStream: false)
        defer { server.stop() }
        let socket = makeSocket(port: server.port, reliable: false)
        let recorder = DelegateRecorder()
        socket.delegate = recorder

        let active = expectation(description: "active")
        recorder.onActive = { active.fulfill() }
        socket.observe(queue: queue, activeTimeout: 3000)
        wait(for: [active], timeout: 5)

        let link = socket.link(userObject: nil)
        let received = expectation(description: "received")
        let payload = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        link.setReadHandler(queue: queue) { packets, error in
            XCTAssertNil(error)
            if let packets, packets.contains(payload) {
                received.fulfill()
            }
        }
        link.writePacket(payload, completionHandler: nil)
        wait(for: [received], timeout: 5)
        socket.shutdown()
    }

    func test_udp_multipleDatagramsPreserved() throws {
        let server = try EchoServer(isStream: false)
        defer { server.stop() }
        let socket = makeSocket(port: server.port, reliable: false)
        let recorder = DelegateRecorder()
        socket.delegate = recorder
        let active = expectation(description: "active")
        recorder.onActive = { active.fulfill() }
        socket.observe(queue: queue, activeTimeout: 3000)
        wait(for: [active], timeout: 5)

        let link = socket.link(userObject: nil)
        let payloads = [Data([1]), Data([2, 2]), Data([3, 3, 3])]
        let received = expectation(description: "received all")
        let seen = Locked<Set<Data>>([])
        link.setReadHandler(queue: queue) { packets, _ in
            guard let packets else { return }
            seen.mutate { set in
                packets.forEach { set.insert($0) }
                if Set(payloads).isSubset(of: set) {
                    received.fulfill()
                }
            }
        }
        // one datagram per packet; no coalescing
        for payload in payloads {
            link.writePacket(payload, completionHandler: nil)
        }
        wait(for: [received], timeout: 5)
        socket.shutdown()
    }

    func test_udp_batchReportsSendFailureAfterConnectionCloses() throws {
        let server = try EchoServer(isStream: false)
        defer { server.stop() }
        let socket = makeSocket(port: server.port, reliable: false)
        let recorder = DelegateRecorder()
        socket.delegate = recorder

        let active = expectation(description: "active")
        recorder.onActive = { active.fulfill() }
        socket.observe(queue: queue, activeTimeout: 3000)
        wait(for: [active], timeout: 5)

        let link = socket.link(userObject: nil)
        let shutdown = expectation(description: "shutdown")
        recorder.onShutdown = { _ in shutdown.fulfill() }
        socket.shutdown()
        wait(for: [shutdown], timeout: 5)

        let completed = expectation(description: "batch completion")
        link.writePackets([Data([1]), Data([2]), Data([3])]) { error in
            XCTAssertNotNil(error)
            completed.fulfill()
        }
        wait(for: [completed], timeout: 5)
    }

    // MARK: State / lifecycle

    func test_connectRefused_reportsTimeoutNotActive() {
        // nothing is listening on this loopback port -> never .ready
        let socket = makeSocket(port: 9, reliable: true)
        let recorder = DelegateRecorder()
        socket.delegate = recorder

        let timedOut = expectation(description: "timeout")
        let detailedTimeout = expectation(description: "detailed timeout")
        recorder.onTimeout = { timedOut.fulfill() }
        recorder.onDetailedTimeout = { error in
            let connectionError = error as? ConnectionError
            XCTAssertEqual(connectionError?.code, .connectionRefused)
            XCTAssertEqual(connectionError?.stage, .socketConnection)
            detailedTimeout.fulfill()
        }
        recorder.onActive = { XCTFail("must not become active without a server") }
        socket.observe(queue: queue, activeTimeout: 800)
        wait(for: [timedOut, detailedTimeout], timeout: 3)
        socket.shutdown()
    }

    func test_shutdown_reportsSingleTerminalEvent() throws {
        let server = try EchoServer(isStream: false)
        defer { server.stop() }
        let socket = makeSocket(port: server.port, reliable: false)
        let recorder = DelegateRecorder()
        socket.delegate = recorder
        let active = expectation(description: "active")
        recorder.onActive = { active.fulfill() }
        socket.observe(queue: queue, activeTimeout: 3000)
        wait(for: [active], timeout: 5)

        let shutdownCount = Locked(0)
        let didShutdown = expectation(description: "shutdown")
        recorder.onShutdown = { _ in
            shutdownCount.mutate { $0 += 1 }
            didShutdown.fulfill()
        }
        // double shutdown must still produce exactly one terminal event
        socket.shutdown()
        socket.shutdown()
        wait(for: [didShutdown], timeout: 5)

        let settle = expectation(description: "settle")
        queue.asyncAfter(deadline: .now() + .milliseconds(200)) { settle.fulfill() }
        wait(for: [settle], timeout: 2)
        XCTAssertEqual(shutdownCount.value, 1)
        XCTAssertTrue(socket.isShutdown)
    }

    // MARK: Helpers

    private func makeSocket(port: UInt16, reliable: Bool) -> NWConnectionSocket {
        let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
        return NWConnectionSocket(
            endpoint: endpoint,
            parameters: reliable ? .tcp : .udp,
            isReliable: reliable,
            remoteHost: "127.0.0.1",
            remotePort: port
        )
    }
}

// MARK: - Test doubles

private final class DelegateRecorder: GenericSocketDelegate, @unchecked Sendable {
    var onActive: (() -> Void)?
    var onTimeout: (() -> Void)?
    var onDetailedTimeout: ((Error) -> Void)?
    var onShutdown: ((Bool) -> Void)?
    var onBetterPath: (() -> Void)?

    func socketDidTimeout(_ socket: GenericSocket) {
        onTimeout?()
    }

    func socket(_ socket: GenericSocket, didTimeoutWith error: Error) {
        onDetailedTimeout?(error)
        socketDidTimeout(socket)
    }

    func socketDidBecomeActive(_ socket: GenericSocket) {
        onActive?()
    }

    func socket(_ socket: GenericSocket, didShutdownWithFailure failure: Bool) {
        onShutdown?(failure)
    }

    func socketHasBetterPath(_ socket: GenericSocket) {
        onBetterPath?()
    }
}

/// A minimal loopback echo server for TCP or UDP, bound to an ephemeral port.
private final class EchoServer: @unchecked Sendable {
    private(set) var port: UInt16 = 0
    private let listener: NWListener
    private let queue = DispatchQueue(label: "EchoServer")
    private var connections: [NWConnection] = []

    init(isStream: Bool) throws {
        let parameters: NWParameters = isStream ? .tcp : .udp
        listener = try NWListener(using: parameters, on: .any)

        // stored properties are all initialized; safe to capture self now
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { [weak self] state in
            if case .ready = state {
                self?.port = self?.listener.port?.rawValue ?? 0
                ready.signal()
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.queue.async { self.connections.append(connection) }
            connection.start(queue: self.queue)
            EchoServer.echo(connection, isStream: isStream)
        }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)
    }

    private static func echo(_ connection: NWConnection, isStream: Bool) {
        if isStream {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, isComplete, error in
                if let data, !data.isEmpty {
                    connection.send(content: data, completion: .contentProcessed { _ in })
                }
                if error == nil, !isComplete {
                    echo(connection, isStream: true)
                }
            }
        } else {
            connection.receiveMessage { data, _, _, error in
                if let data {
                    connection.send(content: data, completion: .contentProcessed { _ in })
                }
                if error == nil {
                    echo(connection, isStream: false)
                }
            }
        }
    }

    /// Gracefully closes every accepted connection (sends a stream FIN), so a
    /// client's pending receive completes with `isComplete`.
    func closeConnections() {
        queue.async {
            for connection in self.connections {
                connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
            }
        }
    }

    func stop() {
        queue.sync {
            connections.forEach { $0.cancel() }
            connections.removeAll()
        }
        listener.cancel()
    }
}

/// Minimal lock box for test-side shared state.
private final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: Value

    init(_ value: Value) {
        _value = value
    }

    var value: Value {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }

    func mutate(_ block: (inout Value) -> Void) {
        lock.lock()
        block(&_value)
        lock.unlock()
    }
}
