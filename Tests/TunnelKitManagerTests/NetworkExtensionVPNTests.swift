import NetworkExtension
import Testing
@testable import TunnelKitManager

@Suite("NetworkExtension VPN manager selection")
struct NetworkExtensionVPNTests {
    @Test("Installation retains only the selected manager")
    func installationRetainsOnlySelectedManager() {
        let selectedManager = NETunnelProviderManager()
        let duplicateManager = NETunnelProviderManager()
        let obsoleteManager = NETunnelProviderManager()

        let managersToRemove = NetworkExtensionVPN.obsoleteManagers(
            from: [selectedManager, duplicateManager, obsoleteManager],
            retaining: selectedManager
        )

        #expect(managersToRemove.count == 2)
        #expect(managersToRemove[0] === duplicateManager)
        #expect(managersToRemove[1] === obsoleteManager)
    }
}
