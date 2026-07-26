//
//  ProbePacket.swift
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

/// Crafts and parses the raw IP packets used to probe tunnel connectivity.
///
/// Only what is required by validation is implemented: ICMP/ICMPv6 echo and
/// DNS over UDP. All parsers validate declared packet lengths before reading
/// protocol fields, so truncated or deliberately malformed input is harmless.
public enum ProbePacket {

    // MARK: Crafting

    /**
     Builds an IPv4 ICMP or IPv6 ICMPv6 echo request.

     `source` and `destination` must be numeric addresses of the same family.
     */
    public static func icmpEchoRequest(
        source: String,
        destination: String,
        identifier: UInt16,
        sequence: UInt16
    ) -> Data? {
        if let sourceBytes = ipv4Bytes(source), let destinationBytes = ipv4Bytes(destination) {
            var icmp = Data()
            icmp.append(8 as UInt8) // ICMP echo request
            icmp.append(0 as UInt8)
            icmp.append(contentsOf: [0, 0])
            appendUInt16(&icmp, identifier)
            appendUInt16(&icmp, sequence)
            icmp.append(contentsOf: "TunnelKitProbe??".utf8)
            setChecksum(&icmp, at: 2, checksum(icmp))
            return ipv4Packet(
                source: sourceBytes,
                destination: destinationBytes,
                protocolNumber: 1,
                payload: icmp
            )
        }

        guard let sourceBytes = ipv6Bytes(source), let destinationBytes = ipv6Bytes(destination) else {
            return nil
        }
        var icmp = Data()
        icmp.append(128 as UInt8) // ICMPv6 echo request
        icmp.append(0 as UInt8)
        icmp.append(contentsOf: [0, 0])
        appendUInt16(&icmp, identifier)
        appendUInt16(&icmp, sequence)
        icmp.append(contentsOf: "TunnelKitProbe??".utf8)
        let pseudoHeader = ipv6PseudoHeader(
            source: sourceBytes,
            destination: destinationBytes,
            nextHeader: 58,
            payloadLength: icmp.count
        )
        setChecksum(&icmp, at: 2, checksum(pseudoHeader + icmp))
        return ipv6Packet(
            source: sourceBytes,
            destination: destinationBytes,
            nextHeader: 58,
            payload: icmp
        )
    }

    /**
     Builds an IPv4 or IPv6 UDP packet carrying a DNS A query.

     `source` and `destination` must be numeric addresses of the same family.
     A response must contain at least one answer to qualify as end-to-end
     connectivity evidence.
     */
    public static func dnsQuery(
        source: String,
        destination: String,
        sourcePort: UInt16,
        transactionId: UInt16,
        hostname: String
    ) -> Data? {
        guard sourcePort != 0, let question = dnsQuestion(hostname) else {
            return nil
        }

        var dns = Data()
        appendUInt16(&dns, transactionId)
        appendUInt16(&dns, 0x0100) // standard query, recursion desired
        appendUInt16(&dns, 1)
        appendUInt16(&dns, 0)
        appendUInt16(&dns, 0)
        appendUInt16(&dns, 0)
        dns.append(question)

        guard dns.count <= Int(UInt16.max) - 8 else {
            return nil
        }
        var udp = Data()
        appendUInt16(&udp, sourcePort)
        appendUInt16(&udp, 53)
        appendUInt16(&udp, UInt16(8 + dns.count))
        appendUInt16(&udp, 0)
        udp.append(dns)

        if let sourceBytes = ipv4Bytes(source), let destinationBytes = ipv4Bytes(destination) {
            return ipv4Packet(
                source: sourceBytes,
                destination: destinationBytes,
                protocolNumber: 17,
                payload: udp
            )
        }

        guard let sourceBytes = ipv6Bytes(source), let destinationBytes = ipv6Bytes(destination) else {
            return nil
        }
        let pseudoHeader = ipv6PseudoHeader(
            source: sourceBytes,
            destination: destinationBytes,
            nextHeader: 17,
            payloadLength: udp.count
        )
        var udpChecksum = checksum(pseudoHeader + udp)
        if udpChecksum == 0 {
            udpChecksum = .max // RFC 768: a computed zero is transmitted as all ones
        }
        setChecksum(&udp, at: 6, udpChecksum)
        return ipv6Packet(
            source: sourceBytes,
            destination: destinationBytes,
            nextHeader: 17,
            payload: udp
        )
    }

    // MARK: Parsing

    /// Checks whether `packet` is an ICMP/ICMPv6 echo reply matching `identifier`.
    public static func isICMPEchoReply(_ packet: Data, identifier: UInt16) -> Bool {
        matchesICMPEchoReply(
            packet,
            identifier: identifier,
            sequence: nil,
            source: nil,
            destination: nil
        )
    }

    /// Checks whether an echo reply matches both the probe identifier and sequence.
    public static func isICMPEchoReply(_ packet: Data, identifier: UInt16, sequence: UInt16) -> Bool {
        matchesICMPEchoReply(
            packet,
            identifier: identifier,
            sequence: sequence,
            source: nil,
            destination: nil
        )
    }

    /// Internal strict matcher used by the validator to reject spoofed replies.
    static func isICMPEchoReply(
        _ packet: Data,
        identifier: UInt16,
        sequence: UInt16,
        source: String,
        destination: String
    ) -> Bool {
        matchesICMPEchoReply(
            packet,
            identifier: identifier,
            sequence: sequence,
            source: source,
            destination: destination
        )
    }

    /**
     Checks whether `packet` is a successful DNS response from port 53 to
     `sourcePort` with `transactionId`.

     A response with a DNS error code or no answers does not establish access
     to the requested external resource and therefore does not match.
     */
    public static func isDNSResponse(_ packet: Data, sourcePort: UInt16, transactionId: UInt16) -> Bool {
        isDNSResponse(
            packet,
            sourcePort: sourcePort,
            transactionId: transactionId,
            source: nil,
            destination: nil
        )
    }

    /// Internal strict matcher used by the validator to reject other DNS flows.
    static func isDNSResponse(
        _ packet: Data,
        sourcePort: UInt16,
        transactionId: UInt16,
        source: String,
        destination: String
    ) -> Bool {
        isDNSResponse(
            packet,
            sourcePort: sourcePort,
            transactionId: transactionId,
            source: Optional(source),
            destination: Optional(destination)
        )
    }

    /// Returns whether a string is a numeric IPv4 or IPv6 address.
    static func isNumericIPAddress(_ address: String) -> Bool {
        ipv4Bytes(address) != nil || ipv6Bytes(address) != nil
    }

    /// Returns whether a hostname can be encoded as an uncompressed DNS name.
    static func isValidDNSHostname(_ hostname: String) -> Bool {
        dnsQuestion(hostname) != nil
    }

    private static func isDNSResponse(
        _ packet: Data,
        sourcePort: UInt16,
        transactionId: UInt16,
        source: String?,
        destination: String?
    ) -> Bool {
        guard let parsedPacket = ipPayload(packet),
              parsedPacket.nextHeader == 17,
              address(source, matches: parsedPacket.source),
              address(destination, matches: parsedPacket.destination) else {
            return false
        }
        let udp = parsedPacket.payload
        guard udp.count >= 20,
              readUInt16(udp, at: 0) == 53,
              readUInt16(udp, at: 2) == sourcePort,
              let udpLength = readUInt16(udp, at: 4),
              udpLength >= 20,
              Int(udpLength) <= udp.count,
              readUInt16(udp, at: 8) == transactionId,
              let flags = readUInt16(udp, at: 10),
              flags & 0x8000 != 0,
              flags & 0x000F == 0,
              let answerCount = readUInt16(udp, at: 14),
              answerCount > 0 else {
            return false
        }
        return true
    }

    // MARK: Address helpers

    /// Returns whether two numeric IP strings represent the same address.
    static func addressesEqual(_ first: String, _ second: String) -> Bool {
        if let firstBytes = ipv4Bytes(first), let secondBytes = ipv4Bytes(second) {
            return firstBytes == secondBytes
        }
        if let firstBytes = ipv6Bytes(first), let secondBytes = ipv6Bytes(second) {
            return firstBytes == secondBytes
        }
        return false
    }

    // MARK: Private parsing

    private struct ParsedIPPacket {
        let nextHeader: UInt8

        let payload: Data

        let source: [UInt8]

        let destination: [UInt8]
    }

    private static func matchesICMPEchoReply(
        _ packet: Data,
        identifier: UInt16,
        sequence: UInt16?,
        source: String?,
        destination: String?
    ) -> Bool {
        guard let parsedPacket = ipPayload(packet),
              address(source, matches: parsedPacket.source),
              address(destination, matches: parsedPacket.destination) else {
            return false
        }
        let expectedType: UInt8
        switch parsedPacket.nextHeader {
        case 1:
            expectedType = 0

        case 58:
            expectedType = 129

        default:
            return false
        }
        let icmp = parsedPacket.payload
        guard icmp.count >= 8,
              icmp[icmp.startIndex] == expectedType,
              icmp[icmp.startIndex + 1] == 0,
              readUInt16(icmp, at: 4) == identifier else {
            return false
        }
        if let sequence {
            return readUInt16(icmp, at: 6) == sequence
        }
        return true
    }

    private static func ipPayload(_ packet: Data) -> ParsedIPPacket? {
        guard let first = packet.first else {
            return nil
        }
        switch first >> 4 {
        case 4:
            return ipv4Payload(packet)

        case 6:
            return ipv6Payload(packet)

        default:
            return nil
        }
    }

    private static func ipv4Payload(_ packet: Data) -> ParsedIPPacket? {
        guard packet.count >= 20 else {
            return nil
        }
        let headerLength = Int(packet[packet.startIndex] & 0x0F) * 4
        guard headerLength >= 20,
              headerLength <= packet.count,
              let totalLength = readUInt16(packet, at: 2),
              Int(totalLength) >= headerLength,
              Int(totalLength) <= packet.count,
              let fragmentation = readUInt16(packet, at: 6),
              fragmentation & 0x3FFF == 0 else {
            return nil
        }
        let payloadStart = packet.startIndex + headerLength
        let payloadEnd = packet.startIndex + Int(totalLength)
        return ParsedIPPacket(
            nextHeader: packet[packet.startIndex + 9],
            payload: packet.subdata(in: payloadStart..<payloadEnd),
            source: Array(packet[(packet.startIndex + 12)..<(packet.startIndex + 16)]),
            destination: Array(packet[(packet.startIndex + 16)..<(packet.startIndex + 20)])
        )
    }

    private static func ipv6Payload(_ packet: Data) -> ParsedIPPacket? {
        guard packet.count >= 40,
              let declaredPayloadLength = readUInt16(packet, at: 4),
              40 + Int(declaredPayloadLength) <= packet.count else {
            return nil
        }

        let packetEnd = packet.startIndex + 40 + Int(declaredPayloadLength)
        var nextHeader = packet[packet.startIndex + 6]
        var payloadStart = packet.startIndex + 40
        var extensionCount = 0

        while isIPv6ExtensionHeader(nextHeader) {
            guard extensionCount < 8, payloadStart + 2 <= packetEnd else {
                return nil
            }
            let followingHeader = packet[payloadStart]
            let extensionLength: Int
            switch nextHeader {
            case 44: // Fragment: L4 fields are unsafe unless the packet is whole
                return nil

            case 51: // Authentication Header
                extensionLength = (Int(packet[payloadStart + 1]) + 2) * 4

            default:
                extensionLength = (Int(packet[payloadStart + 1]) + 1) * 8
            }
            guard extensionLength >= 8, payloadStart + extensionLength <= packetEnd else {
                return nil
            }
            payloadStart += extensionLength
            nextHeader = followingHeader
            extensionCount += 1
        }

        return ParsedIPPacket(
            nextHeader: nextHeader,
            payload: packet.subdata(in: payloadStart..<packetEnd),
            source: Array(packet[(packet.startIndex + 8)..<(packet.startIndex + 24)]),
            destination: Array(packet[(packet.startIndex + 24)..<(packet.startIndex + 40)])
        )
    }

    private static func isIPv6ExtensionHeader(_ nextHeader: UInt8) -> Bool {
        switch nextHeader {
        case 0, 43, 44, 51, 60:
            return true

        default:
            return false
        }
    }

    // MARK: Packet crafting

    private static func ipv4Packet(
        source: [UInt8],
        destination: [UInt8],
        protocolNumber: UInt8,
        payload: Data
    ) -> Data? {
        guard source.count == 4,
              destination.count == 4,
              payload.count <= Int(UInt16.max) - 20 else {
            return nil
        }
        var packet = Data()
        packet.append(0x45 as UInt8)
        packet.append(0 as UInt8)
        appendUInt16(&packet, UInt16(20 + payload.count))
        appendUInt16(&packet, UInt16.random(in: .min ... .max))
        appendUInt16(&packet, 0x4000)
        packet.append(64 as UInt8)
        packet.append(protocolNumber)
        packet.append(contentsOf: [0, 0])
        packet.append(contentsOf: source)
        packet.append(contentsOf: destination)
        setChecksum(&packet, at: 10, checksum(packet))
        packet.append(payload)
        return packet
    }

    private static func ipv6Packet(
        source: [UInt8],
        destination: [UInt8],
        nextHeader: UInt8,
        payload: Data
    ) -> Data? {
        guard source.count == 16,
              destination.count == 16,
              payload.count <= Int(UInt16.max) else {
            return nil
        }
        var packet = Data()
        packet.append(contentsOf: [0x60, 0, 0, 0])
        appendUInt16(&packet, UInt16(payload.count))
        packet.append(nextHeader)
        packet.append(64 as UInt8)
        packet.append(contentsOf: source)
        packet.append(contentsOf: destination)
        packet.append(payload)
        return packet
    }

    private static func ipv6PseudoHeader(
        source: [UInt8],
        destination: [UInt8],
        nextHeader: UInt8,
        payloadLength: Int
    ) -> Data {
        var header = Data()
        header.append(contentsOf: source)
        header.append(contentsOf: destination)
        appendUInt32(&header, UInt32(payloadLength))
        header.append(contentsOf: [0, 0, 0])
        header.append(nextHeader)
        return header
    }

    private static func ipv4Bytes(_ address: String) -> [UInt8]? {
        var parsedAddress = in_addr()
        guard address.withCString({ inet_pton(AF_INET, $0, &parsedAddress) }) == 1 else {
            return nil
        }
        return withUnsafeBytes(of: parsedAddress) { Array($0) }
    }

    private static func ipv6Bytes(_ address: String) -> [UInt8]? {
        var parsedAddress = in6_addr()
        guard address.withCString({ inet_pton(AF_INET6, $0, &parsedAddress) }) == 1 else {
            return nil
        }
        return withUnsafeBytes(of: parsedAddress) { Array($0) }
    }

    private static func address(_ expected: String?, matches bytes: [UInt8]) -> Bool {
        guard let expected else {
            return true
        }
        if bytes.count == 4 {
            return ipv4Bytes(expected) == bytes
        }
        if bytes.count == 16 {
            return ipv6Bytes(expected) == bytes
        }
        return false
    }

    private static func dnsQuestion(_ hostname: String) -> Data? {
        let canonicalHostname = hostname.hasSuffix(".") ? String(hostname.dropLast()) : hostname
        guard !canonicalHostname.isEmpty,
              canonicalHostname.utf8.allSatisfy({ $0 < 0x80 }),
              !canonicalHostname.contains("..") else {
            return nil
        }
        let labels = canonicalHostname.split(separator: ".", omittingEmptySubsequences: false)
        var question = Data()
        for label in labels {
            let bytes = Array(label.utf8)
            guard !bytes.isEmpty, bytes.count <= 63 else {
                return nil
            }
            question.append(UInt8(bytes.count))
            question.append(contentsOf: bytes)
        }
        guard question.count + 1 <= 255 else {
            return nil
        }
        question.append(0 as UInt8)
        appendUInt16(&question, 1) // A
        appendUInt16(&question, 1) // IN
        return question
    }

    // MARK: Byte helpers

    private static func appendUInt16(_ data: inout Data, _ value: UInt16) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xFF))
    }

    private static func appendUInt32(_ data: inout Data, _ value: UInt32) {
        data.append(UInt8(value >> 24))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    private static func readUInt16(_ data: Data, at offset: Int) -> UInt16? {
        guard offset >= 0, offset <= data.count - 2 else {
            return nil
        }
        let index = data.startIndex + offset
        return UInt16(data[index]) << 8 | UInt16(data[index + 1])
    }

    private static func setChecksum(_ data: inout Data, at offset: Int, _ value: UInt16) {
        guard offset >= 0, offset <= data.count - 2 else {
            return
        }
        data[data.startIndex + offset] = UInt8(value >> 8)
        data[data.startIndex + offset + 1] = UInt8(value & 0xFF)
    }

    /// RFC 1071 Internet checksum.
    private static func checksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var index = data.startIndex
        while index + 1 < data.endIndex {
            sum &+= UInt32(data[index]) << 8 | UInt32(data[index + 1])
            index += 2
        }
        if index < data.endIndex {
            sum &+= UInt32(data[index]) << 8
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) &+ (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }
}
