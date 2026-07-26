import Foundation
import TunnelKitCore

/// Implements OpenVPN's `block-ipv6` behavior for packet tunnels.
///
/// IPv6 packets are captured by the tunnel route but are not sent to the VPN
/// server. Instead, the originating application receives an ICMPv6 no-route
/// response so Happy Eyeballs can immediately continue with IPv4.
final class IPv6BlockingTunnelInterface: TunnelInterface {
    private let wrappedInterface: TunnelInterface

    init(wrapping wrappedInterface: TunnelInterface) {
        self.wrappedInterface = wrappedInterface
    }

    var isPersistent: Bool {
        wrappedInterface.isPersistent
    }

    func setReadHandler(queue: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
        wrappedInterface.setReadHandler(queue: queue) { [weak self] packets, error in
            guard let self, let packets else {
                handler(packets, error)
                return
            }

            var forwardedPackets = [Data]()
            var rejectionPackets = [Data]()
            forwardedPackets.reserveCapacity(packets.count)

            for packet in packets {
                if IPv6NoRoutePacket.isIPv6(packet) {
                    if let rejectionPacket = IPv6NoRoutePacket.response(to: packet) {
                        rejectionPackets.append(rejectionPacket)
                    }
                } else {
                    forwardedPackets.append(packet)
                }
            }

            if !rejectionPackets.isEmpty {
                wrappedInterface.writePackets(rejectionPackets, completionHandler: nil)
            }
            handler(forwardedPackets, error)
        }
    }

    func writePacket(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        guard !IPv6NoRoutePacket.isIPv6(packet) else {
            completionHandler?(nil)
            return
        }
        wrappedInterface.writePacket(packet, completionHandler: completionHandler)
    }

    func writePackets(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let ipv4Packets = packets.filter { !IPv6NoRoutePacket.isIPv6($0) }
        guard !ipv4Packets.isEmpty else {
            completionHandler?(nil)
            return
        }
        wrappedInterface.writePackets(ipv4Packets, completionHandler: completionHandler)
    }
}

enum IPv6NoRoutePacket {
    private static let ipv6HeaderLength = 40
    private static let icmpv6HeaderLength = 8
    private static let minimumIPv6MTU = 1_280
    private static let icmpv6NextHeader: UInt8 = 58
    private static let destinationUnreachableType: UInt8 = 1
    private static let noRouteCode: UInt8 = 0

    static func isIPv6(_ packet: Data) -> Bool {
        packet.first.map { $0 >> 4 == 6 } ?? false
    }

    static func response(to packet: Data) -> Data? {
        guard isIPv6(packet), packet.count >= ipv6HeaderLength else {
            return nil
        }

        let originalSource = Array(packet[8..<24])
        let originalDestination = Array(packet[24..<40])
        guard isValidUnicastSource(originalSource), !isMulticast(originalDestination) else {
            return nil
        }

        if packet[6] == icmpv6NextHeader,
           packet.count > ipv6HeaderLength,
           packet[ipv6HeaderLength] < 128 {
            return nil
        }

        let maximumQuotedLength = minimumIPv6MTU - ipv6HeaderLength - icmpv6HeaderLength
        let quotedPacket = Array(packet.prefix(maximumQuotedLength))
        let payloadLength = icmpv6HeaderLength + quotedPacket.count

        var icmpPayload = [UInt8](
            repeating: 0,
            count: icmpv6HeaderLength
        )
        icmpPayload[0] = destinationUnreachableType
        icmpPayload[1] = noRouteCode
        icmpPayload.append(contentsOf: quotedPacket)

        let responseSource = originalDestination
        let responseDestination = originalSource
        let checksum = checksum(
            source: responseSource,
            destination: responseDestination,
            payload: icmpPayload
        )
        icmpPayload[2] = UInt8(checksum >> 8)
        icmpPayload[3] = UInt8(checksum & 0xff)

        var response = [UInt8]()
        response.reserveCapacity(ipv6HeaderLength + payloadLength)
        response.append(contentsOf: [0x60, 0, 0, 0])
        appendUInt16(UInt16(payloadLength), to: &response)
        response.append(icmpv6NextHeader)
        response.append(64)
        response.append(contentsOf: responseSource)
        response.append(contentsOf: responseDestination)
        response.append(contentsOf: icmpPayload)
        return Data(response)
    }

    private static func checksum(
        source: [UInt8],
        destination: [UInt8],
        payload: [UInt8]
    ) -> UInt16 {
        var pseudoHeader = [UInt8]()
        pseudoHeader.reserveCapacity(40 + payload.count)
        pseudoHeader.append(contentsOf: source)
        pseudoHeader.append(contentsOf: destination)
        appendUInt32(UInt32(payload.count), to: &pseudoHeader)
        pseudoHeader.append(contentsOf: [0, 0, 0, icmpv6NextHeader])
        pseudoHeader.append(contentsOf: payload)

        var sum: UInt32 = 0
        var byteIndex = 0
        while byteIndex + 1 < pseudoHeader.count {
            sum += UInt32(pseudoHeader[byteIndex]) << 8
                | UInt32(pseudoHeader[byteIndex + 1])
            byteIndex += 2
        }
        if byteIndex < pseudoHeader.count {
            sum += UInt32(pseudoHeader[byteIndex]) << 8
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return ~UInt16(sum)
    }

    private static func isValidUnicastSource(_ address: [UInt8]) -> Bool {
        !address.allSatisfy { $0 == 0 } && !isMulticast(address)
    }

    private static func isMulticast(_ address: [UInt8]) -> Bool {
        address.first == 0xff
    }

    private static func appendUInt16(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xff))
    }

    private static func appendUInt32(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8((value >> 24) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }
}
