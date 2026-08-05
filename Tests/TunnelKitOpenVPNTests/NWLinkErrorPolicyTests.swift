//
//  NWLinkErrorPolicyTests.swift
//  TunnelKitOpenVPNTests
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
import Network
import TunnelKitCore
@testable import TunnelKitOpenVPNAppExtension

final class NWLinkErrorPolicyTests: XCTestCase {

    func test_givenBufferPressure_whenClassifying_thenWrapsAsTransient() {
        for code in [POSIXErrorCode.ENOBUFS, .ENOMEM, .EAGAIN, .EINTR, .EMSGSIZE, .ENOSPC] {
            let error = NWError.posix(code)
            XCTAssertTrue(NWLinkErrorPolicy.isRecoverable(error), "\(code) should be recoverable")
            let classified = NWLinkErrorPolicy.classify(error, operation: "write")
            XCTAssertTrue(classified is TransientLinkError)
            XCTAssertTrue(classified.isTransientLinkFailure)
        }
    }

    func test_givenDeadLink_whenClassifying_thenPassesErrorThrough() {
        for code in [POSIXErrorCode.ECONNREFUSED, .ENETDOWN, .ENETUNREACH, .ETIMEDOUT] {
            let error = NWError.posix(code)
            XCTAssertFalse(NWLinkErrorPolicy.isRecoverable(error), "\(code) must fail the link")
            let classified = NWLinkErrorPolicy.classify(error, operation: "read")
            XCTAssertFalse(classified is TransientLinkError)
            XCTAssertFalse(classified.isTransientLinkFailure)
        }
    }

    func test_givenNonPOSIXError_whenClassifying_thenPassesErrorThrough() {
        let error = NWError.dns(DNSServiceErrorType(kDNSServiceErr_Timeout))
        XCTAssertFalse(NWLinkErrorPolicy.isRecoverable(error))
        XCTAssertFalse(NWLinkErrorPolicy.classify(error, operation: "read") is TransientLinkError)
    }

    /// A datagram link must never turn a single failed send into a link failure:
    /// there is nothing to lose but that packet, and escalating it reconnected the
    /// tunnel during saturated uploads. Liveness comes from the connection state
    /// and the keep-alive timeout instead.
    func test_givenAnySendFailureOnDatagramLink_whenReportingUpwards_thenIsTransient() throws {
        let connection = NWConnection(
            to: .hostPort(host: "127.0.0.1", port: 1),
            using: .udp
        )
        let link = NWUDPLink(
            connection: connection,
            xorMethod: nil,
            remoteHost: "127.0.0.1",
            remotePort: 1
        )
        // errors a saturated or torn-down datagram socket really produces
        let failures: [NWError] = [
            .posix(.ENOBUFS),
            .posix(.ECONNREFUSED),
            .posix(.EHOSTUNREACH),
            .posix(.ENETUNREACH),
            .posix(.ECANCELED),
            .posix(.EPIPE)
        ]
        for failure in failures {
            let reported = try XCTUnwrap(link.reportableSendFailure(failure))
            XCTAssertTrue(
                reported.isTransientLinkFailure,
                "\(failure) must not tear down a datagram link"
            )
        }
        XCTAssertNil(link.reportableSendFailure(nil))
        connection.cancel()
    }
}
