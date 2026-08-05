//
//  TransientLinkErrorTests.swift
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
@testable import TunnelKitCore

final class TransientLinkErrorTests: XCTestCase {

    func test_givenWrappedError_whenClassifying_thenIsTransient() {
        let error = TransientLinkError(operation: "write", underlying: POSIXError(.ENOBUFS))
        XCTAssertTrue(error.isTransientLinkFailure)
    }

    func test_givenPOSIXErrorUnderLoad_whenClassifying_thenIsTransient() {
        for code in [POSIXErrorCode.ENOBUFS, .ENOMEM, .EAGAIN, .EINTR, .EMSGSIZE, .ENOSPC] {
            XCTAssertTrue(
                POSIXError(code).isTransientLinkFailure,
                "\(code) should be recoverable"
            )
        }
    }

    /// `NWError.posix` reaches the session bridged as an `NSError` in the POSIX
    /// domain, so classification must work without importing Network.
    func test_givenBridgedPOSIXNSError_whenClassifying_thenIsTransient() {
        let error = NSError(domain: NSPOSIXErrorDomain, code: Int(ENOBUFS))
        XCTAssertTrue(error.isTransientLinkFailure)
    }

    func test_givenLinkInvalidatingError_whenClassifying_thenIsNotTransient() {
        for code in [POSIXErrorCode.ECONNREFUSED, .ENETDOWN, .ENETUNREACH, .ETIMEDOUT, .ECONNRESET] {
            XCTAssertFalse(
                POSIXError(code).isTransientLinkFailure,
                "\(code) must still fail the link"
            )
        }
        XCTAssertFalse(
            ConnectionError(.connectionLost, stage: .monitoring).isTransientLinkFailure
        )
        XCTAssertFalse(NSError(domain: "other", code: Int(ENOBUFS)).isTransientLinkFailure)
    }
}
