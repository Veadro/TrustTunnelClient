#pragma once

#include <memory>
#include <string_view>

namespace ag {

class VpnMacDnsSettingsManagerImpl;
using VpnMacDnsSettingsManagerImplPtr = std::unique_ptr<VpnMacDnsSettingsManagerImpl>;

/**
 * Class for setting DNS server of macOS.
 */
class VpnMacDnsSettingsManager {
    VpnMacDnsSettingsManagerImplPtr m_pimpl;
    struct ConstructorAccess {};
public:
    VpnMacDnsSettingsManager(ConstructorAccess access, std::string_view dns_server);
    ~VpnMacDnsSettingsManager();

    static std::unique_ptr<VpnMacDnsSettingsManager> create(std::string_view dns_server) {
        auto manager = std::make_unique<VpnMacDnsSettingsManager>(ConstructorAccess{}, dns_server);
        if (!manager->m_pimpl) {
            manager.reset();
        }
        return manager;
    }

    VpnMacDnsSettingsManager(const VpnMacDnsSettingsManager &) = delete;
    VpnMacDnsSettingsManager(VpnMacDnsSettingsManager &&) = delete;
    void operator=(const VpnMacDnsSettingsManager &) = delete;
    void operator=(VpnMacDnsSettingsManager &&) = delete;
};

} // namespace ag
