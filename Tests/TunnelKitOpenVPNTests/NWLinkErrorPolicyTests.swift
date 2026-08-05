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
}
