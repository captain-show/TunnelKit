import Foundation
import Testing
@testable import TunnelKitManager

@Suite("VPN notification payloads")
struct VPNNotificationTests {
    @Test("Missing payloads are represented explicitly")
    func missingPayloads() {
        let notification = Notification(name: VPNNotification.didChangeStatus)

        #expect(notification.vpnIsEnabledIfPresent == nil)
        #expect(notification.vpnStatusIfPresent == nil)
        #expect(notification.vpnErrorIfPresent == nil)
        #expect(notification.vpnIsEnabled == false)
        #expect(notification.vpnStatus == .disconnected)
    }

    @Test("Payloads can be attached and removed")
    func payloadRoundTrip() {
        var notification = Notification(name: VPNNotification.didChangeStatus)
        let expectedError = TunnelKitManagerError.disconnectionTimedOut(lastStatus: .disconnecting)

        notification.vpnIsEnabledIfPresent = true
        notification.vpnStatusIfPresent = .connecting
        notification.vpnErrorIfPresent = expectedError

        #expect(notification.vpnIsEnabledIfPresent == true)
        #expect(notification.vpnStatusIfPresent == .connecting)
        #expect(notification.vpnErrorIfPresent is TunnelKitManagerError)

        notification.vpnErrorIfPresent = nil

        #expect(notification.vpnErrorIfPresent == nil)
    }
}
