//
//  ProbePacketTests.swift
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
@testable import TunnelKitCore

final class ProbePacketTests: XCTestCase {

    // MARK: ICMP

    func test_icmpEchoRequest_wellFormed() throws {
        let packet = try XCTUnwrap(ProbePacket.icmpEchoRequest(
            source: "10.8.0.2",
            destination: "10.8.0.1",
            identifier: 0xBEEF,
            sequence: 1
        ))

        XCTAssertGreaterThanOrEqual(packet.count, 20 + 8)
        XCTAssertEqual(packet[0], 0x45) // IPv4, IHL 5
        XCTAssertEqual(packet[9], 1) // ICMP
        XCTAssertEqual(Array(packet[12...15]), [10, 8, 0, 2]) // source
        XCTAssertEqual(Array(packet[16...19]), [10, 8, 0, 1]) // destination
        XCTAssertEqual(packet[20], 8) // echo request
        XCTAssertEqual(UInt16(packet[24]) << 8 | UInt16(packet[25]), 0xBEEF)

        // total length field must match actual size
        XCTAssertEqual(Int(UInt16(packet[2]) << 8 | UInt16(packet[3])), packet.count)

        // IP header checksum must validate (sum of header including checksum == 0xFFFF one's complement)
        XCTAssertEqual(onesComplementSum(packet.prefix(20)), 0xFFFF)
        // ICMP checksum must validate over the ICMP payload
        XCTAssertEqual(onesComplementSum(packet.dropFirst(20)), 0xFFFF)
    }

    func test_icmpEchoRequest_invalidAddressReturnsNil() {
        XCTAssertNil(ProbePacket.icmpEchoRequest(source: "not-an-ip", destination: "10.8.0.1", identifier: 1, sequence: 1))
        XCTAssertNil(ProbePacket.icmpEchoRequest(source: "10.8.0.2", destination: "fe80::1", identifier: 1, sequence: 1))
        XCTAssertNil(ProbePacket.icmpEchoRequest(source: "", destination: "", identifier: 1, sequence: 1))
    }

    func test_icmpV6EchoRequest_wellFormedAndMatchesReply() throws {
        let packet = try XCTUnwrap(ProbePacket.icmpEchoRequest(
            source: "fd00::2",
            destination: "2606:4700:4700::1111",
            identifier: 0xCAFE,
            sequence: 7
        ))

        XCTAssertEqual(packet[0] >> 4, 6)
        XCTAssertEqual(packet[6], 58)
        XCTAssertEqual(packet[40], 128)
        XCTAssertEqual(UInt16(packet[44]) << 8 | UInt16(packet[45]), 0xCAFE)
        XCTAssertEqual(Int(UInt16(packet[4]) << 8 | UInt16(packet[5])), packet.count - 40)

        let reply = makeEchoReplyIPv6(identifier: 0xCAFE, sequence: 7)
        XCTAssertTrue(ProbePacket.isICMPEchoReply(reply, identifier: 0xCAFE, sequence: 7))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(reply, identifier: 0xCAFE, sequence: 8))
    }

    func test_icmpEchoReply_matching() throws {
        let reply = makeEchoReply(identifier: 0xBEEF)
        XCTAssertTrue(ProbePacket.isICMPEchoReply(reply, identifier: 0xBEEF))
        XCTAssertTrue(ProbePacket.isICMPEchoReply(reply, identifier: 0xBEEF, sequence: 1))
        XCTAssertTrue(ProbePacket.isICMPEchoReply(
            reply,
            identifier: 0xBEEF,
            sequence: 1,
            source: "10.8.0.1",
            destination: "10.8.0.2"
        ))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(reply, identifier: 0xBEE0))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(reply, identifier: 0xBEEF, sequence: 2))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(
            reply,
            identifier: 0xBEEF,
            sequence: 1,
            source: "1.1.1.1",
            destination: "10.8.0.2"
        ))
    }

    func test_icmpEchoReply_rejectsRequestPacket() throws {
        // a looped-back echo REQUEST (type 8) must not match
        let request = try XCTUnwrap(ProbePacket.icmpEchoRequest(
            source: "10.8.0.1",
            destination: "10.8.0.2",
            identifier: 0xBEEF,
            sequence: 1
        ))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(request, identifier: 0xBEEF))
    }

    func test_icmpEchoReply_malformedPacketsAreSafe() {
        // must never crash or match on garbage/truncated input
        XCTAssertFalse(ProbePacket.isICMPEchoReply(Data(), identifier: 1))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(Data([0x45]), identifier: 1))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(Data(repeating: 0, count: 19), identifier: 1))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(Data(repeating: 0, count: 20), identifier: 1))
        XCTAssertFalse(ProbePacket.isICMPEchoReply(Data(repeating: 0xFF, count: 64), identifier: 1))

        // IPv6 version nibble
        var v6 = Data(repeating: 0, count: 48)
        v6[0] = 0x60
        XCTAssertFalse(ProbePacket.isICMPEchoReply(v6, identifier: 1))

        // claims IHL beyond packet size
        var badIhl = Data(repeating: 0, count: 24)
        badIhl[0] = 0x4F
        badIhl[9] = 1
        XCTAssertFalse(ProbePacket.isICMPEchoReply(badIhl, identifier: 1))

        // Declared total length is shorter than the header.
        var badTotalLength = makeEchoReply(identifier: 1)
        badTotalLength[2] = 0
        badTotalLength[3] = 19
        XCTAssertFalse(ProbePacket.isICMPEchoReply(badTotalLength, identifier: 1))

        // Non-initial fragments do not contain safe transport offsets.
        var fragment = makeEchoReply(identifier: 1)
        fragment[6] = 0
        fragment[7] = 1
        XCTAssertFalse(ProbePacket.isICMPEchoReply(fragment, identifier: 1))
    }

    // MARK: DNS

    func test_dnsQuery_wellFormed() throws {
        let packet = try XCTUnwrap(ProbePacket.dnsQuery(
            source: "10.8.0.2",
            destination: "10.8.0.1",
            sourcePort: 40000,
            transactionId: 0xABCD,
            hostname: "example.org"
        ))

        XCTAssertEqual(packet[9], 17) // UDP
        let udp = packet.dropFirst(20)
        XCTAssertEqual(UInt16(udp[udp.startIndex]) << 8 | UInt16(udp[udp.startIndex + 1]), 40000) // src port
        XCTAssertEqual(UInt16(udp[udp.startIndex + 2]) << 8 | UInt16(udp[udp.startIndex + 3]), 53) // dst port
        let dns = udp.dropFirst(8)
        XCTAssertEqual(UInt16(dns[dns.startIndex]) << 8 | UInt16(dns[dns.startIndex + 1]), 0xABCD) // txid

        // encoded question: 7"example"3"org"0
        let question = Data(dns.dropFirst(12))
        XCTAssertEqual(question[0], 7)
        XCTAssertEqual(String(data: question[1...7], encoding: .utf8), "example")
        XCTAssertEqual(question[8], 3)
    }

    func test_dnsQuery_invalidHostnameReturnsNil() {
        XCTAssertNil(ProbePacket.dnsQuery(source: "10.8.0.2", destination: "10.8.0.1", sourcePort: 1, transactionId: 1, hostname: ""))
        let tooLongLabel = String(repeating: "a", count: 64)
        XCTAssertNil(ProbePacket.dnsQuery(source: "10.8.0.2", destination: "10.8.0.1", sourcePort: 1, transactionId: 1, hostname: "\(tooLongLabel).com"))
        XCTAssertNil(ProbePacket.dnsQuery(source: "10.8.0.2", destination: "10.8.0.1", sourcePort: 1, transactionId: 1, hostname: "a..example"))
        XCTAssertNil(ProbePacket.dnsQuery(source: "10.8.0.2", destination: "10.8.0.1", sourcePort: 1, transactionId: 1, hostname: "пример.рф"))
        XCTAssertNil(ProbePacket.dnsQuery(source: "10.8.0.2", destination: "10.8.0.1", sourcePort: 0, transactionId: 1, hostname: "example.com"))
    }

    func test_dnsV6Query_wellFormedAndMatchesReply() throws {
        let packet = try XCTUnwrap(ProbePacket.dnsQuery(
            source: "fd00::2",
            destination: "2001:4860:4860::8888",
            sourcePort: 40_000,
            transactionId: 0xABCD,
            hostname: "example.org"
        ))

        XCTAssertEqual(packet[0] >> 4, 6)
        XCTAssertEqual(packet[6], 17)
        XCTAssertNotEqual(UInt16(packet[46]) << 8 | UInt16(packet[47]), 0)
        XCTAssertTrue(ProbePacket.isDNSResponse(
            makeDNSResponseIPv6(toPort: 40_000, transactionId: 0xABCD),
            sourcePort: 40_000,
            transactionId: 0xABCD
        ))
    }

    func test_dnsResponse_matching() {
        let response = makeDNSResponse(toPort: 40000, transactionId: 0xABCD)
        XCTAssertTrue(ProbePacket.isDNSResponse(response, sourcePort: 40000, transactionId: 0xABCD))
        XCTAssertTrue(ProbePacket.isDNSResponse(
            response,
            sourcePort: 40000,
            transactionId: 0xABCD,
            source: "10.8.0.1",
            destination: "10.8.0.2"
        ))
        XCTAssertFalse(ProbePacket.isDNSResponse(response, sourcePort: 40001, transactionId: 0xABCD))
        XCTAssertFalse(ProbePacket.isDNSResponse(response, sourcePort: 40000, transactionId: 0xABCE))
        XCTAssertFalse(ProbePacket.isDNSResponse(
            response,
            sourcePort: 40000,
            transactionId: 0xABCD,
            source: "8.8.8.8",
            destination: "10.8.0.2"
        ))

        var nxdomain = response
        nxdomain[31] = 0x83
        XCTAssertFalse(ProbePacket.isDNSResponse(nxdomain, sourcePort: 40000, transactionId: 0xABCD))

        var noAnswers = response
        noAnswers[34] = 0
        noAnswers[35] = 0
        XCTAssertFalse(ProbePacket.isDNSResponse(noAnswers, sourcePort: 40000, transactionId: 0xABCD))

        var queryInsteadOfResponse = response
        queryInsteadOfResponse[30] = 0x01
        XCTAssertFalse(ProbePacket.isDNSResponse(queryInsteadOfResponse, sourcePort: 40000, transactionId: 0xABCD))
    }

    func test_dnsResponse_malformedPacketsAreSafe() {
        XCTAssertFalse(ProbePacket.isDNSResponse(Data(), sourcePort: 1, transactionId: 1))
        XCTAssertFalse(ProbePacket.isDNSResponse(Data(repeating: 0, count: 28), sourcePort: 1, transactionId: 1))
        XCTAssertFalse(ProbePacket.isDNSResponse(Data(repeating: 0xFF, count: 64), sourcePort: 1, transactionId: 1))

        var truncatedByIPLength = makeDNSResponse(toPort: 1, transactionId: 1)
        truncatedByIPLength[2] = 0
        truncatedByIPLength[3] = 60
        XCTAssertFalse(ProbePacket.isDNSResponse(truncatedByIPLength, sourcePort: 1, transactionId: 1))

        var oversizedUDP = makeDNSResponse(toPort: 1, transactionId: 1)
        oversizedUDP[24] = 0
        oversizedUDP[25] = 40
        XCTAssertFalse(ProbePacket.isDNSResponse(oversizedUDP, sourcePort: 1, transactionId: 1))
    }

    // MARK: Helpers

    /// Sums 16-bit words one's-complement style; a valid checksummed block sums to 0xFFFF.
    private func onesComplementSum(_ data: Data) -> UInt32 {
        var sum: UInt32 = 0
        let bytes = Array(data)
        var index = 0
        while index + 1 < bytes.count {
            sum &+= UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count {
            sum &+= UInt32(bytes[index]) << 8
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) &+ (sum >> 16)
        }
        return sum
    }
}

/// Builds a minimal ICMP echo reply as a server would return it.
func makeEchoReply(identifier: UInt16, sequence: UInt16 = 1) -> Data {
    var packet = Data()
    packet.append(contentsOf: [0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0] as [UInt8])
    packet.append(contentsOf: [10, 8, 0, 1]) // src: gateway
    packet.append(contentsOf: [10, 8, 0, 2]) // dst: local
    packet.append(contentsOf: [0, 0, 0, 0] as [UInt8]) // type 0 (reply), code 0, checksum
    packet.append(UInt8(identifier >> 8))
    packet.append(UInt8(identifier & 0xFF))
    packet.append(UInt8(sequence >> 8))
    packet.append(UInt8(sequence & 0xFF))
    return packet
}

/// Builds a minimal ICMPv6 echo reply.
func makeEchoReplyIPv6(identifier: UInt16, sequence: UInt16 = 1) -> Data {
    var packet = Data()
    packet.append(contentsOf: [0x60, 0, 0, 0, 0, 8, 58, 64] as [UInt8])
    packet.append(contentsOf: [0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11])
    packet.append(contentsOf: [0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    packet.append(contentsOf: [129, 0, 0, 0] as [UInt8])
    packet.append(UInt8(identifier >> 8))
    packet.append(UInt8(identifier & 0xFF))
    packet.append(UInt8(sequence >> 8))
    packet.append(UInt8(sequence & 0xFF))
    return packet
}

/// Builds a minimal DNS response from port 53.
func makeDNSResponse(toPort port: UInt16, transactionId: UInt16) -> Data {
    var packet = Data()
    packet.append(contentsOf: [0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 17, 0, 0] as [UInt8])
    packet.append(contentsOf: [10, 8, 0, 1])
    packet.append(contentsOf: [10, 8, 0, 2])
    packet.append(contentsOf: [0, 53] as [UInt8]) // src port 53
    packet.append(UInt8(port >> 8))
    packet.append(UInt8(port & 0xFF))
    packet.append(contentsOf: [0, 20, 0, 0] as [UInt8]) // length, checksum
    packet.append(UInt8(transactionId >> 8))
    packet.append(UInt8(transactionId & 0xFF))
    packet.append(contentsOf: [0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0] as [UInt8]) // response flags
    return packet
}

/// Builds a minimal DNS response inside IPv6/UDP.
func makeDNSResponseIPv6(toPort port: UInt16, transactionId: UInt16) -> Data {
    var packet = Data()
    packet.append(contentsOf: [0x60, 0, 0, 0, 0, 20, 17, 64] as [UInt8])
    packet.append(contentsOf: [0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88])
    packet.append(contentsOf: [0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    packet.append(contentsOf: [0, 53] as [UInt8])
    packet.append(UInt8(port >> 8))
    packet.append(UInt8(port & 0xFF))
    packet.append(contentsOf: [0, 20, 0x12, 0x34] as [UInt8])
    packet.append(UInt8(transactionId >> 8))
    packet.append(UInt8(transactionId & 0xFF))
    packet.append(contentsOf: [0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0] as [UInt8])
    return packet
}
