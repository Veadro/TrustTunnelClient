#include <net/network_manager.h>

#include <mutex>
#include <utility>

#include "common/cache.h"

namespace ag {

static struct NetworkManagerHolder {
    VpnNetworkManager manager = {
            .dns = dns_manager_create(), // single DNS manager for all VPN clients
            .socket = nullptr,           // each VPN client has its own socket manager
    };
    std::mutex guard;
    ag::LruTimeoutCache<std::string, bool> app_domain_cache;

    NetworkManagerHolder()
            : app_domain_cache(100, std::chrono::minutes(10)) {
    }

    ~NetworkManagerHolder() {
        clear();
    }

    void clear() {
        dns_manager_destroy(std::exchange(this->manager.dns, nullptr));
        socket_manager_destroy(std::exchange(this->manager.socket, nullptr));
    }
} g_network_manager_holder;

VpnNetworkManager *vpn_network_manager_get() {
    return new VpnNetworkManager{g_network_manager_holder.manager.dns, socket_manager_create()};
}

void vpn_network_manager_destroy(VpnNetworkManager *m) {
    socket_manager_destroy(std::exchange(m->socket, nullptr));
    delete m;
}

bool vpn_network_manager_update_dns(VpnDnsServers servers) {
    std::vector<std::string> v;
    v.reserve(servers.size);
    for (size_t i = 0; i < servers.size; ++i) {
        v.emplace_back(servers.data[i]);
    }
    return dns_manager_set_servers(g_network_manager_holder.manager.dns, std::move(v));
}

void vpn_network_manager_notify_app_request_domain(const char *domain, int timeout_ms) {
    std::scoped_lock l(g_network_manager_holder.guard);
    if (timeout_ms >= 0) {
        g_network_manager_holder.app_domain_cache.insert(domain, false, std::chrono::milliseconds(timeout_ms));
    } else {
        g_network_manager_holder.app_domain_cache.insert(domain, false);
    }
}

bool vpn_network_manager_check_app_request_domain(const char *domain) {
    std::scoped_lock l(g_network_manager_holder.guard);
    return (bool) g_network_manager_holder.app_domain_cache.get(domain);
}

} // namespace ag
