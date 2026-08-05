//
//  DataPathToleranceTests.swift
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
@testable import TunnelKitCore
import CTunnelKitCore
import CTunnelKitOpenVPNCore
import CTunnelKitOpenVPNProtocol

/// A single unusable inbound packet must cost that packet and nothing else.
///
/// `decryptPackets` used to abort the whole batch and report an error, which
/// `OpenVPNSession` escalated to a session stop. Bulk traffic is what makes such
/// packets appear (corruption, a compression framing the client cannot decode),
/// so the tunnel dropped as soon as anything was downloaded through it.
final class DataPathToleranceTests: XCTestCase {
    private let cipherKey = try! SecureRandom.safeData(length: 32)

    private let hmacKey = try! SecureRandom.safeData(length: 32)

    // MARK: Batch tolerance

    func test_givenCorruptedPacketInBatch_whenDecrypting_thenKeepsGoodPackets() throws {
        let path = makeDataPath(framing: .disabled)
        let payloads = [
            Data(repeating: 0xaa, count: 1200),
            Data(repeating: 0xbb, count: 800),
            Data(repeating: 0xcc, count: 1400)
        ]
        var encrypted = try XCTUnwrap(path.encryptPackets(payloads, key: 0))
        XCTAssertEqual(encrypted.count, 3)

        // flip a ciphertext byte of the middle packet: authentication fails
        var corrupted = encrypted[1]
        corrupted[corrupted.count - 1] ^= 0xff
        encrypted[1] = corrupted

        let decrypted = try XCTUnwrap(path.decryptPackets(encrypted, keepAlive: nil))
        XCTAssertEqual(decrypted, [payloads[0], payloads[2]])
        XCTAssertEqual(path.droppedInboundPackets, 1)
    }

    func test_givenEveryPacketCorrupted_whenDecrypting_thenReportsNoErrorAndNoPackets() throws {
        let path = makeDataPath(framing: .disabled)
        let encrypted = try XCTUnwrap(path.encryptPackets([Data(repeating: 0xaa, count: 1200)], key: 0))
        var corrupted = encrypted[0]
        corrupted[corrupted.count - 1] ^= 0xff

        // must not throw: an unusable packet is not a session-level failure
        let decrypted = try XCTUnwrap(path.decryptPackets([corrupted], keepAlive: nil))
        XCTAssertTrue(decrypted.isEmpty)
        XCTAssertEqual(path.droppedInboundPackets, 1)
    }

    /// The app does not link an LZO provider, so a server that compresses a
    /// (compressible) download makes the client see LZO-framed packets. Those
    /// must be dropped, not fatal.
    func test_givenLZOFramedPacketWithoutProvider_whenDecrypting_thenDropsOnlyThatPacket() throws {
        let box = makeBox()
        // the peer frames packets verbatim, this client parses compLZO framing
        let peerPath = makeDataPath(framing: .disabled, box: box)
        let clientPath = makeDataPath(framing: .compLZO, box: box)

        var lzoFramed = Data([0x66]) // DataPacketLZOCompress
        lzoFramed.append(Data(repeating: 0x5a, count: 1000))
        var noCompressFramed = Data([0xfa]) // DataPacketNoCompress
        noCompressFramed.append(Data(repeating: 0x45, count: 1000))

        let encrypted = try XCTUnwrap(peerPath.encryptPackets([lzoFramed, noCompressFramed], key: 0))
        let decrypted = try XCTUnwrap(clientPath.decryptPackets(encrypted, keepAlive: nil))

        XCTAssertEqual(decrypted, [noCompressFramed.dropFirst()])
        XCTAssertEqual(clientPath.droppedInboundPackets, 1)
        XCTAssertEqual(clientPath.droppedCompressedInboundPackets, 1)
    }

    func test_givenEmptyPayload_whenParsingCompressionFraming_thenDropsWithoutOverreading() throws {
        let box = makeBox()
        let peerPath = makeDataPath(framing: .disabled, box: box)
        let clientPath = makeDataPath(framing: .compLZO, box: box)

        // a zero-length payload leaves no room for the framing byte
        let encrypted = try XCTUnwrap(peerPath.encryptPackets([Data()], key: 0))
        let decrypted = try XCTUnwrap(clientPath.decryptPackets(encrypted, keepAlive: nil))

        XCTAssertTrue(decrypted.isEmpty)
        XCTAssertEqual(clientPath.droppedCompressedInboundPackets, 1)
    }

    func test_givenReplayedPacket_whenDecrypting_thenDropsDuplicateAndCounts() throws {
        let path = makeDataPath(framing: .disabled, usesReplayProtection: true)
        let payload = Data(repeating: 0xab, count: 900)
        let encrypted = try XCTUnwrap(path.encryptPackets([payload], key: 0))

        XCTAssertEqual(try XCTUnwrap(path.decryptPackets(encrypted, keepAlive: nil)), [payload])
        XCTAssertTrue(try XCTUnwrap(path.decryptPackets(encrypted, keepAlive: nil)).isEmpty)
        XCTAssertEqual(path.droppedReplayedInboundPackets, 1)
        XCTAssertEqual(path.droppedInboundPackets, 0)
    }

    // MARK: Framing round trips

    /// Full-MTU packets only ever appear under load, so a size-dependent framing
    /// defect would look exactly like "downloads break the tunnel".
    func test_givenEveryFraming_whenRoundTrippingAllSizes_thenPayloadIsPreserved() throws {
        let framings: [CompressionFramingNative] = [.disabled, .compress, .compressV2, .compLZO]
        let sizes = [1, 2, 3, 15, 16, 17, 63, 576, 1279, 1280, 1399, 1400, 1401, 1499, 1500]

        for framing in framings {
            let path = makeDataPath(framing: framing)
            for size in sizes {
                let payload = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 &+ 0x40) })
                let encrypted = try XCTUnwrap(path.encryptPackets([payload], key: 0))
                let decrypted = try XCTUnwrap(path.decryptPackets(encrypted, keepAlive: nil))
                XCTAssertEqual(
                    decrypted.first,
                    payload,
                    "framing \(framing.rawValue) lost bytes at size \(size)"
                )
            }
            XCTAssertEqual(path.droppedInboundPackets, 0, "framing \(framing.rawValue) dropped packets")
        }
    }

    /// stub-v2 prepends two bytes, so reporting a one-byte header returned a
    /// trailing byte of adjacent buffer memory with every such packet.
    func test_givenCompressV2AmbiguousFirstByte_whenRoundTripping_thenPayloadIsExact() throws {
        let path = makeDataPath(framing: .compressV2)
        var payload = Data([0x50]) // DataPacketV2Indicator
        payload.append(Data(repeating: 0x37, count: 1399))

        let encrypted = try XCTUnwrap(path.encryptPackets([payload], key: 0))
        let decrypted = try XCTUnwrap(path.decryptPackets(encrypted, keepAlive: nil))

        XCTAssertEqual(decrypted.first, payload)
    }

    // MARK: Helpers

    private func makeBox() -> CryptoBox {
        let box = CryptoBox(cipherAlgorithm: "aes-256-gcm", digestAlgorithm: nil)
        try! box.configure(
            withCipherEncKey: cipherKey,
            cipherDecKey: cipherKey,
            hmacEncKey: hmacKey,
            hmacDecKey: hmacKey
        )
        return box
    }

    private func makeDataPath(
        framing: CompressionFramingNative,
        box: CryptoBox? = nil,
        usesReplayProtection: Bool = false
    ) -> DataPath {
        let box = box ?? makeBox()
        return DataPath(
            encrypter: box.encrypter().dataPathEncrypter(),
            decrypter: box.decrypter().dataPathDecrypter(),
            peerId: PacketPeerIdDisabled,
            compressionFraming: framing,
            compressionAlgorithm: .disabled,
            maxPackets: 100,
            usesReplayProtection: usesReplayProtection
        )
    }
}
