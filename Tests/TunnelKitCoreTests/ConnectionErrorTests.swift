//
//  ConnectionErrorTests.swift
//  TunnelKitCoreTests
//
//  Copyright (c) 2026 Davide De Rosa. All rights reserved.
//
//  This file is part of TunnelKit.
//

import XCTest
@testable import TunnelKitCore

final class ConnectionErrorTests: XCTestCase {

    func test_everyCodeHasUniqueStableNSErrorCodeAndRoundTrips() throws {
        var numericCodes = Set<Int>()

        for code in ConnectionError.Code.allCases {
            let original = ConnectionError(
                code,
                stage: .validation,
                message: "Detailed failure",
                diagnostics: ["probe": "dns", "attempt": "2"]
            )
            let nsError = original as NSError

            XCTAssertEqual(nsError.domain, ConnectionError.errorDomain)
            XCTAssertTrue(numericCodes.insert(nsError.code).inserted, "Duplicate NSError code for \(code)")

            let restored = try XCTUnwrap(ConnectionError(nsError: nsError))
            XCTAssertEqual(restored.code, original.code)
            XCTAssertEqual(restored.stage, original.stage)
            XCTAssertEqual(restored.message, original.message)
            XCTAssertEqual(restored.diagnostics, original.diagnostics)
            XCTAssertNil(restored.underlying)
        }
    }

    func test_nserrorPayloadNeverSerializesUnderlyingError() {
        let secret = NSError(
            domain: "PrivateUnderlyingError",
            code: 42,
            userInfo: [NSLocalizedDescriptionKey: "token=must-not-cross-xpc"]
        )
        let error = ConnectionError(
            .connectionLost,
            stage: .monitoring,
            message: "Connection lost.",
            underlying: secret,
            diagnostics: ["path": "unsatisfied"]
        )

        let nsError = error as NSError
        let serializedPayload = String(describing: nsError.userInfo)

        XCTAssertNil(nsError.userInfo[NSUnderlyingErrorKey])
        XCTAssertFalse(serializedPayload.contains("must-not-cross-xpc"))
        XCTAssertEqual(nsError.localizedDescription, "Connection lost.")
    }

    func test_rejectsForeignOrUnknownNSError() {
        XCTAssertNil(ConnectionError(nsError: NSError(domain: "Other", code: 1001)))
        XCTAssertNil(ConnectionError(nsError: NSError(domain: ConnectionError.errorDomain, code: -1)))
    }
}
