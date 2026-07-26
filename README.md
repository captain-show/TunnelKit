![iOS 17.6+](https://img.shields.io/badge/iOS-17.6+-green.svg)
![macOS 14+](https://img.shields.io/badge/macOS-14+-green.svg)
[![License GPLv3](https://img.shields.io/badge/license-GPLv3-lightgray.svg)](LICENSE)

[![Unit Tests](https://github.com/passepartoutvpn/tunnelkit/actions/workflows/test.yml/badge.svg)](https://github.com/passepartoutvpn/tunnelkit/actions/workflows/test.yml)
[![Release](https://github.com/passepartoutvpn/tunnelkit/actions/workflows/release.yml/badge.svg)](https://github.com/passepartoutvpn/tunnelkit/actions/workflows/release.yml)

# TunnelKit

This library provides a generic framework for VPN development on Apple platforms.

## OpenVPN

TunnelKit comes with a simplified Swift/Obj-C implementation of the [OpenVPN®][dep-openvpn] protocol. Its crypto layer uses [OpenSSL 3.6.2][dep-openssl], distributed by the pinned [`openssl-apple` 3.6.300 package][dep-openssl-package].

The client is known to work with OpenVPN® 2.3+ servers.

- [x] Handshake and tunneling over UDP or TCP
- [x] Ciphers
    - AES-CBC (128/192/256 bit)
    - AES-GCM (128/192/256 bit, 2.4)
- [x] HMAC digests
    - SHA-1
    - SHA-2 (224/256/384/512 bit)
- [x] NCP (Negotiable Crypto Parameters, 2.4)
    - Server-side
- [x] TLS handshake
    - Server validation (CA, EKU)
    - Client certificate
- [x] TLS wrapping
    - Authentication (`--tls-auth`)
    - Encryption (`--tls-crypt`)
- [x] Compression framing
    - Via `--comp-lzo` (deprecated in 2.4)
    - Via `--compress`
- [x] Compression algorithms
    - LZO (via `--comp-lzo` or `--compress lzo`)
- [x] Key renegotiation
- [x] Replay protection (hardcoded window)

The library therefore supports compression framing, just not newer compression. Remember to match server-side compression and framing, otherwise the client will shut down with an error. E.g. if server has `comp-lzo no`, client must use `compressionFraming = .compLZO`.

### Support for .ovpn configuration

TunnelKit can parse .ovpn configuration files. Below are a few details worth mentioning.

#### Non-standard

- XOR-patch functionality:
    - Multi-byte XOR Masking
        - Via `--scramble xormask <passphrase>`
        - XOR all incoming and outgoing bytes by the passphrase given
    - XOR Position Masking
        - Via `--scramble xorptrpos`
        - XOR all bytes by their position in the array
    - Packet Reverse Scramble
        - Via `--scramble reverse`
        - Keeps the first byte and reverses the rest of the array
    - XOR Scramble Obfuscate
        - Via `--scramble obfuscate <passphrase>`
        - Performs a combination of the three above (specifically `xormask <passphrase>` -> `xorptrpos` -> `reverse` -> `xorptrpos` for reading, and the opposite for writing) 
    - See [Tunnelblick website][about-tunnelblick-xor] for more details (Patch was written in accordance with Tunnelblick's patch for compatibility)

#### Unsupported

- UDP fragmentation, i.e. `--fragment`
- Compression via `--compress` other than empty or `lzo`
- Connecting via proxy
- External file references (inline `<block>` only)
- Static key encryption (non-TLS)
- `<connection>` blocks
- `net_gateway` literals in routes

#### Ignored

- Some MTU overrides
    - `--link-mtu` and variants
    - `--mssfix`
- Multiple `--remote` with different `host` values (first wins)
- Static client-side routes

Many other flags are ignored too but it's normally not an issue.

## WireGuard

TunnelKit offers a user-friendly API to the modern [WireGuard®][dep-wireguard] protocol.

TunnelKit pins [`wireguard-apple-xcframework` 0.0.7][dep-wireguard-xcframework],
which distributes WireGuardKit as a prebuilt XCFramework for iOS devices, the
iOS Simulator and macOS. SwiftPM resolves and links it automatically; consumer
projects no longer need Go, `make`, an external build target or a custom build
script.

## Connection validation

Validation is fail-closed unless a profile explicitly selects `.disabled`.
OpenVPN is only reported as connected after the current connection attempt has
completed all of these steps:

1. the TLS handshake and `PUSH_REPLY` negotiation must complete;
2. the tunnel network settings must apply successfully;
3. a configured external ICMP or DNS probe must receive a valid response through the tunnel; the default is a DNS query for `example.com` through tunnel DNS;
4. the successful probe must remain valid through the stabilization period.

After connecting, OpenVPN repeats the same end-to-end validation every 15
seconds. A failed check immediately switches NetworkExtension to reasserting;
failures that persist through the 15-second grace period trigger a reconnect.
Extension subclasses may tune `connectivityWatchdogInterval` and
`connectivityFailureGracePeriod`; setting the interval to 0 is an explicit
runtime-monitoring opt-out.

On supported systems, WireGuard with validation enabled actively triggers and
verifies a fresh handshake from the selected routed peers required by the
validation policy,
then requires an end-to-end probe and continuously monitors both handshake
freshness and probe results after connecting. On iOS 18+ and macOS 15+, DNS
and ICMP probes are bound to the tunnel's `virtualInterface`, so the default
verifies external DNS access. On iOS 17.6 and macOS 14, NetworkExtension does
not expose `virtualInterface`; enabled validation, including `.default`, fails
with `ConnectionError.Code.unsupportedConfiguration` instead of returning
`connected` from handshake evidence alone. `.disabled` is the only legacy
opt-out.

For both protocols, a gateway reply and unrelated inbound traffic are only
diagnostics. Neither can count as end-to-end success. If a mandatory step
fails, the attempt ends in a typed `ConnectionError`, with a compatible
`TunnelKitOpenVPNError` or `TunnelKitWireGuardError` summary. Detailed,
secret-free `OpenVPNConnectionError` and `WireGuardConnectionError` snapshots
are available from `ProviderConfiguration.lastConnectionError` across the
app-extension boundary.

Validation is configured per profile via `ProviderConfiguration.connectionValidation`:

```swift
var cfg = OpenVPN.ProviderConfiguration(...)
cfg.connectionValidation = .default   // DNS answer for example.com through tunnel DNS
cfg.connectionValidation = .strict    // all probes, including diagnostics, must pass
cfg.connectionValidation = .disabled  // explicit legacy opt-out

// or fine-tune:
var validation = ConnectionValidationOptions()
validation.probes = [
    .gatewayPing,
    .dns(hostname: "probe.your-domain.com", server: nil)
]
validation.policy = .any
validation.probeTimeout = 4
validation.probeAttempts = 3
validation.stabilizationPeriod = 2
cfg.connectionValidation = validation
```

`example.com` is a reserved, stable default endpoint and can be replaced with
one you control. A custom ping target must be a numeric external address; the
tunnel address and gateway are rejected. An enabled configuration with no
usable end-to-end probe always fails closed.

For DoH/DoT profiles, an implicit `.dns(..., server: nil)` probe would send
plaintext UDP/53 and therefore cannot validate the configured encrypted DNS
transport. Configure a numeric `.ping` target or an explicit plaintext DNS
probe server and remove every implicit DNS probe; otherwise the profile fails
with `unsupportedConfiguration` instead of producing a misleading result.

The internal lifecycle follows an explicit state machine:
`idle → preparing → connecting → negotiating → validating → connected → disconnecting → disconnected/failed`.

## Installation

### Requirements

- iOS 17.6+ / macOS 14+
- Xcode 16+ and Swift 6
- Git (preinstalled with Xcode Command Line Tools)

### Migration from deprecated NetworkExtension transports

The public `NETCPSocket` and `NEUDPSocket` types, which depended on Apple's
deprecated `NWTCPConnection` and `NWUDPSession` APIs, have been removed. Code
that constructed either concrete socket must migrate to `NWConnectionSocket`
and configure an `NWEndpoint` plus `NWParameters`. OpenVPN's internal
`NETCPLink` and `NEUDPLink` implementations were replaced by
`NWConnection`-backed links as part of the same migration.

### Demo

Download the library codebase locally:

    $ git clone https://github.com/passepartoutvpn/tunnelkit.git

There are demo targets containing a simple app for testing the tunnels. Open `Demo/TunnelKit.xcodeproj` in Xcode and run it.

For the VPN to work properly, the demo requires:

- _App Groups_ and _Keychain Sharing_ capabilities
- App IDs with _Packet Tunnel_ entitlements

both in the main app and the tunnel extension targets.

In order to test connectivity in your own environment, modify the file `Demo/Demo/UI/Configuration.swift` to match your VPN server parameters.

Example:

    private let ca = CryptoContainer(pem: """
	-----BEGIN CERTIFICATE-----
	MIIFJDCC...
	-----END CERTIFICATE-----
    """)

Make sure to also update the identifiers in `Demo/Demo/UI/Configuration.swift`
according to your developer account and target bundle identifiers:

    private let appGroup = "..."
    private let tunnelIdentifier = "..."

Remember that the App Group on macOS requires a team ID prefix.

## Documentation

The library is split into several modules, in order to decouple the low-level protocol implementation from the platform-specific bridging, namely the [NetworkExtension][ne-home] VPN framework.

Full documentation of the public interface can be generated by opening the package in Xcode and running "Build Documentation".

### TunnelKit

This component includes convenient classes to control the VPN tunnel from your app without the NetworkExtension headaches. Have a look at `VPN` implementations:

- `MockVPN` (default, useful to test on simulator)
- `NetworkExtensionVPN` (anything based on NetworkExtension)

`NetworkExtensionVPN.currentStatus(ofTunnelBundleIdentifier:)` now throws
preference-loading errors instead of treating them as "not installed".
Reconnect waits until the previous tunnel is actually stopped and throws
`TunnelKitManagerError.disconnectionTimedOut` after five seconds rather than
starting a second connection over a still-disconnecting one. Disconnected
status notifications include NetworkExtension's last disconnect error in
`vpnErrorIfPresent` when the system provides one.

### TunnelKitOpenVPN

Provides the entities to interact with the OpenVPN tunnel.

### TunnelKitOpenVPNAppExtension

Contains the `NEPacketTunnelProvider` implementation of a OpenVPN tunnel.

### TunnelKitWireGuard

Provides the entities to interact with the WireGuard tunnel.

### TunnelKitWireGuardAppExtension

Contains the `NEPacketTunnelProvider` implementation of a WireGuard tunnel.

## License

Copyright (c) 2024 Davide De Rosa. All rights reserved.

### Part I

This project is licensed under the [GPLv3][license-content].

### Part II

As seen in [libsignal-protocol-c][license-signal]:

> Additional Permissions For Submission to Apple App Store: Provided that you are otherwise in compliance with the GPLv3 for each covered work you convey (including without limitation making the Corresponding Source available in compliance with Section 6 of the GPLv3), the Author also grants you the additional permission to convey through the Apple App Store non-source executable versions of the Program as incorporated into each applicable covered work as Executable Versions only under the Mozilla Public License version 2.0 (https://www.mozilla.org/en-US/MPL/2.0/).

### Part III

Part I and II do not apply to the LZO library, which remains licensed under the terms of the GPLv2+.

### Contributing

By contributing to this project you are agreeing to the terms stated in the [Contributor License Agreement (CLA)][contrib-cla].

For more details please see [CONTRIBUTING][contrib-readme].

### Other licenses

A custom TunnelKit license, e.g. for use in proprietary software, may be negotiated [on request][license-contact].

## Credits

- [lzo][dep-lzo-website] - Copyright (c) 1996-2017 Markus F.X.J. Oberhumer
- [PIATunnel][dep-piatunnel-repo] - Copyright (c) 2018-Present Private Internet Access
- [SURFnet][ppl-surfnet]
- [SwiftyBeaver][dep-swiftybeaver-repo] - Copyright (c) 2015 Sebastian Kreutzberger
- [XMB5][ppl-xmb5] for the [XOR patch][ppl-xmb5-xor] - Copyright (c) 2020 Sam Foxman
- [tmthecoder][ppl-tmthecoder] for the complete [XOR patch][ppl-tmthecoder-xor] - Copyright (c) 2022 Tejas Mehta
- [Ridgeline International][dep-wireguard-xcframework] for the prebuilt WireGuardKit XCFramework

### OpenVPN

© Copyright 2022 OpenVPN | OpenVPN is a registered trademark of OpenVPN, Inc.

### WireGuard

© Copyright 2015-2022 Jason A. Donenfeld. All Rights Reserved. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.

### OpenSSL

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. ([https://www.openssl.org/][dep-openssl])

## Contacts

Twitter: [@keeshux][about-twitter]

Website: [passepartoutvpn.app][about-website]

[dep-openvpn]: https://openvpn.net/index.php/open-source/overview.html
[dep-wireguard]: https://www.wireguard.com/
[dep-wireguard-xcframework]: https://github.com/ridgelineinternational/wireguard-apple-xcframework/tree/0.0.7
[dep-openssl]: https://www.openssl.org/
[dep-openssl-package]: https://github.com/passepartoutvpn/openssl-apple/tree/3.6.300

[ne-home]: https://developer.apple.com/documentation/networkextension

[license-content]: LICENSE
[license-signal]: https://github.com/signalapp/libsignal-protocol-c#license
[license-contact]: mailto:license@passepartoutvpn.app
[contrib-cla]: CLA.rst
[contrib-readme]: CONTRIBUTING.md

[dep-piatunnel-repo]: https://github.com/pia-foss/tunnel-apple
[dep-swiftybeaver-repo]: https://github.com/SwiftyBeaver/SwiftyBeaver
[dep-lzo-website]: https://www.oberhumer.com/opensource/lzo/
[ppl-surfnet]: https://www.surf.nl/en/about-surf/subsidiaries/surfnet
[ppl-xmb5]: https://github.com/XMB5
[ppl-xmb5-xor]: https://github.com/passepartoutvpn/tunnelkit/pull/170
[ppl-tmthecoder]: https://github.com/tmthecoder
[ppl-tmthecoder-xor]: https://github.com/passepartoutvpn/tunnelkit/pull/255
[about-tunnelblick-xor]: https://tunnelblick.net/cOpenvpn_xorpatch.html

[about-twitter]: https://twitter.com/keeshux
[about-website]: https://passepartoutvpn.app
