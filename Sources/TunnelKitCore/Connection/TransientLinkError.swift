//
//  TransientLinkError.swift
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

/**
 A link failure that affected a single datagram but left the link usable.

 Datagram transports routinely fail individual sends and receives under load:
 the kernel socket buffer fills up (`ENOBUFS`), the send would block
 (`EAGAIN`), a syscall is interrupted (`EINTR`), memory pressure hits
 (`ENOMEM`). A VPN data path must drop the affected packet and carry on — the
 transport protocol above it (TCP, QUIC) already handles the loss. Tearing the
 tunnel down instead turns a lost packet into a dropped connection, which is
 exactly what happens while saturating the link (e.g. downloading a file).

 Transports wrap such failures in this type so the session can tell them apart
 from failures that really do invalidate the link.
 */
public struct TransientLinkError: Error, CustomStringConvertible {

    /// The link operation that failed (`read`, `write`, ...).
    public let operation: String

    /// The failure reported by the transport.
    public let underlying: Error

    public init(operation: String, underlying: Error) {
        self.operation = operation
        self.underlying = underlying
    }

    public var description: String {
        "TransientLinkError(operation: \(operation), underlying: \(String(describing: underlying)))"
    }
}

extension Error {

    /**
     Whether this failure affected one packet only and the link may keep being
     used.

     Recognizes both the explicit `TransientLinkError` marker and the bare
     POSIX codes that datagram sockets raise under load, so a transport that
     has not been taught to wrap its errors still cannot bring a tunnel down
     over a single lost packet.
     */
    public var isTransientLinkFailure: Bool {
        if self is TransientLinkError {
            return true
        }
        guard let code = posixErrorCode else {
            return false
        }
        return TransientLinkErrorCodes.recoverable.contains(code)
    }

    /// The POSIX code behind this error, when it carries one.
    var posixErrorCode: Int32? {
        if let posixError = self as? POSIXError {
            return posixError.code.rawValue
        }
        // NWError.posix, and anything else bridged from errno, lands here
        let nsError = self as NSError
        guard nsError.domain == NSPOSIXErrorDomain else {
            return nil
        }
        return Int32(nsError.code)
    }
}

/// POSIX failures that a datagram link recovers from by dropping the packet.
enum TransientLinkErrorCodes {
    static let recoverable: Set<Int32> = [
        ENOBUFS,    // socket buffer full: the classic high-throughput failure
        ENOMEM,     // transient memory pressure in the networking stack
        EAGAIN,     // == EWOULDBLOCK, the send would have blocked
        EINTR,      // interrupted syscall
        EMSGSIZE,   // oversized datagram: only this packet is undeliverable
        ENOSPC      // reported in place of ENOBUFS by some paths
    ]
}
