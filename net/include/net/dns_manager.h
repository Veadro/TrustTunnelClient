#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "net/utils.h"
#include "vpn/event_loop.h"

namespace ag {

struct DnsManager;
using DnsChangeSubscriptionId = uint32_t;

enum DnsManagerServersKind {
    /**
     * The original system DNS servers
     */
    DMSK_SYSTEM,
    /**
     * The servers set to the virtual TUN interface set up by an application.
     * Needed to distinct the DNS queries routed to the default peer from the queries
     * routed to arbitrary ones.
     */
    DMSK_TUN_INTERFACE,
};

using DnsChangeNotification = void (*)(void *arg, DnsManagerServersKind);

/**
 * Create a DNS manager
 */
DnsManager *dns_manager_create();

/**
 * Destroy a DNS manager
 */
void dns_manager_destroy(DnsManager *manager);

/**
 * Set DNS servers to be used by the manager
 * @param servers the servers
 * @return true if set successfully, false otherwise
 */
bool dns_manager_set_system_servers(DnsManager *manager, SystemDnsServers servers);

/**
 * Set DNS servers set to tunnel interface
 * @param servers the servers
 * @return true if set successfully, false otherwise
 */
bool dns_manager_set_tunnel_interface_servers(DnsManager *manager, std::vector<std::string> servers);

/**
 * Get the system DNS servers used by the manager
 */
SystemDnsServers dns_manager_get_system_servers(const DnsManager *manager);

/**
 * Get the tunnel interface DNS servers used by the manager
 */
std::vector<std::string> dns_manager_get_tunnel_interface_servers(const DnsManager *manager);

/**
 * Subscribe to DNS servers change event.
 * The `notification` is raised through the `event_loop`.
 * @return Subscription ID in case subscribed successfully
 */
DnsChangeSubscriptionId dns_manager_subscribe_servers_change(
        DnsManager *manager, VpnEventLoop *event_loop, DnsChangeNotification notification, void *notification_arg);

/**
 * Cancel the DNS servers change subscription
 */
void dns_manager_unsubscribe_servers_change(DnsManager *manager, DnsChangeSubscriptionId subscription_id);

} // namespace ag
