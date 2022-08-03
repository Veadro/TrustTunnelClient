#pragma once

#include "net/dns_manager.h"
#include "net/socket_manager.h"
#include "vpn/utils.h"

namespace ag {

/**
 * Network manager of VPN client operations
 */
struct VpnNetworkManager {
    DnsManager *dns;       // DNS manager (optional: needed only for the SOCKS listener)
    SocketManager *socket; // Socket manager
};

using VpnDnsServers = AG_ARRAY_OF(const char *);

/**
 * Get a network manager
 */
VpnNetworkManager *vpn_network_manager_get();

/**
 * Destroy a network manager
 */
void vpn_network_manager_destroy(VpnNetworkManager *m);

/**
 * Set DNS servers
 */
extern "C" WIN_EXPORT bool vpn_network_manager_update_dns(VpnDnsServers servers);

/**
 * Notify that a domain is about to be queried by an application
 * @param domain the domain name
 * @param timeout_ms the amount of time after which the record will be forgotten (negative means default)
 */
extern "C" WIN_EXPORT void vpn_network_manager_notify_app_request_domain(const char *domain, int timeout_ms);

/**
 * Check whether a domain belongs to queries from an application
 */
bool vpn_network_manager_check_app_request_domain(const char *domain);

} // namespace ag
