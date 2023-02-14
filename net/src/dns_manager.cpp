#include <algorithm>
#include <array>
#include <bitset>
#include <mutex>
#include <set>
#include <unordered_map>

#include <magic_enum.hpp>

#include "common/logger.h"
#include "net/dns_manager.h"

namespace ag {

static const Logger logger{"DNS_MANAGER"}; // NOLINT(readability-identifier-naming)
static constexpr size_t AG_UNFILTERED_IPS_NUM =
        std::size(AG_UNFILTERED_DNS_IPS_V4) + std::size(AG_UNFILTERED_DNS_IPS_V6);
static const std::array<sockaddr_storage, AG_UNFILTERED_IPS_NUM> AG_UNFILTERED_DNS_IPS = []() {
    std::array<sockaddr_storage, AG_UNFILTERED_IPS_NUM> arr;
    auto ipv6_begin = std::transform(std::begin(AG_UNFILTERED_DNS_IPS_V4), std::end(AG_UNFILTERED_DNS_IPS_V4),
            arr.begin(), [](std::string_view ip) {
                return sockaddr_from_str(std::string{ip}.c_str());
            });
    std::transform(std::begin(AG_UNFILTERED_DNS_IPS_V6), std::end(AG_UNFILTERED_DNS_IPS_V6), ipv6_begin,
            [](std::string_view ip) {
                return sockaddr_from_str(std::string{ip}.c_str());
            });
    return arr;
}();
static constexpr std::string_view EXTRA_FALLBACK_SYSTEM_DNS[] = {
        "tls://1.1.1.1",
        "tls://8.8.8.8",
};

struct DnsChangeSubscription {
    using PendingNotifications = std::bitset<magic_enum::enum_count<DnsManagerServersKind>()>;

    VpnEventLoop *event_loop = nullptr;
    DnsChangeNotification notification = nullptr;
    void *notification_arg = nullptr;
    event_loop::AutoTaskId notification_task;
    PendingNotifications pending_notifications;
};

struct DnsManager {
    mutable std::mutex mutex;
    SystemDnsServers system_servers;
    std::set<std::string> tun_interface_servers;
    DnsChangeSubscriptionId next_dns_change_subscription_id = 0;
    std::unordered_map<DnsChangeSubscriptionId, DnsChangeSubscription> dns_change_subscriptions;
};

DnsManager *dns_manager_create() {
    auto *manager = new DnsManager{};
    return manager;
}

void dns_manager_destroy(DnsManager *manager) {
    delete manager;
}

static void engage_notifications(DnsManager *self, DnsManagerServersKind kind) {
    struct NotificationTaskContext {
        DnsManager *self;
        DnsChangeSubscriptionId subscription_id;
    };

    for (auto &[subscription_id, subscription] : self->dns_change_subscriptions) {
        subscription.pending_notifications.set(kind);
        if (subscription.notification_task.has_value()) {
            continue;
        }

        subscription.notification_task = event_loop::submit( // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
                subscription.event_loop,
                {
                        .arg =
                                new NotificationTaskContext{
                                        .self = self,
                                        .subscription_id = subscription_id,
                                },
                        .action =
                                [](void *arg, TaskId) {
                                    auto *ctx = (NotificationTaskContext *) arg;
                                    DnsChangeNotification notification = nullptr;
                                    void *notification_arg = nullptr;
                                    DnsChangeSubscription::PendingNotifications pending_notifications;

                                    {
                                        std::unique_lock l(ctx->self->mutex);
                                        auto iter = ctx->self->dns_change_subscriptions.find(ctx->subscription_id);
                                        if (iter != ctx->self->dns_change_subscriptions.end()) {
                                            iter->second.notification_task.release();
                                            notification = iter->second.notification;
                                            notification_arg = iter->second.notification_arg;
                                            pending_notifications = iter->second.pending_notifications;
                                            iter->second.pending_notifications.reset();
                                        }
                                    }

                                    if (notification != nullptr) {
                                        for (DnsManagerServersKind kind :
                                                magic_enum::enum_values<DnsManagerServersKind>()) {
                                            if (pending_notifications.test(kind)) {
                                                notification(notification_arg, kind);
                                            }
                                        }
                                    }
                                },
                        .finalize =
                                [](void *arg) {
                                    delete (NotificationTaskContext *) arg;
                                },
                });
    }
}

static SystemDnsServers filter_out_tun_interface_servers(
        SystemDnsServers servers, const std::set<std::string> &tun_interface_servers) {
    std::erase_if(servers.main, [&](const SystemDnsServer &s) {
        return tun_interface_servers.contains(s.address)
                || (s.resolved_host.has_value() && tun_interface_servers.contains(s.resolved_host->str()));
    });
    std::erase_if(servers.fallback, [&](const std::string &s) {
        return tun_interface_servers.contains(s);
    });
    return servers;
}

struct PrepareResult {
    SystemDnsServers servers;
    bool changed = false;
};

static PrepareResult prepare_system_servers(const DnsManager *self, SystemDnsServers servers) {
    servers = filter_out_tun_interface_servers(std::move(servers), self->tun_interface_servers);

    std::set<std::string> filtered_servers;
    std::transform(servers.main.begin(), servers.main.end(), std::inserter(filtered_servers, filtered_servers.begin()),
            [](const SystemDnsServer &s) {
                return s.address;
            });
    filtered_servers.insert(servers.fallback.begin(), servers.fallback.end());

    std::erase_if(filtered_servers, [](const std::string &s) {
        sockaddr_storage addr = sockaddr_from_str(s.c_str());
        return addr.ss_family != AF_UNSPEC && sockaddr_is_loopback((sockaddr *) &addr);
    });
    std::erase_if(filtered_servers, [](const std::string &s) {
        sockaddr_storage addr = sockaddr_from_str(s.c_str());
        sockaddr_set_port((sockaddr *) &addr, 0);
        return std::any_of(
                std::begin(AG_UNFILTERED_DNS_IPS), std::end(AG_UNFILTERED_DNS_IPS), [&](const sockaddr_storage &i) {
                    return sockaddr_equals((sockaddr *) &i, (sockaddr *) &addr);
                });
    });

    bool add_extra_fallbacks = filtered_servers.empty() && !servers.main.empty() && !servers.fallback.empty();
    if (add_extra_fallbacks) {
        dbglog(logger,
                "Passed servers contain no servers other than ones of tunnel interface, loopback and AdGuard's, "
                "adding extra fallbacks");
        servers.fallback.insert(
                servers.fallback.end(), std::begin(EXTRA_FALLBACK_SYSTEM_DNS), std::end(EXTRA_FALLBACK_SYSTEM_DNS));
    }

    return {
            .servers = std::move(servers),
            .changed = add_extra_fallbacks,
    };
}

bool dns_manager_set_system_servers(DnsManager *self, SystemDnsServers servers) {
    std::unique_lock l(self->mutex);
    dbglog(logger, "{}", servers);
    self->system_servers = std::move(prepare_system_servers(self, servers).servers);
    engage_notifications(self, DMSK_SYSTEM);
    return true;
}

bool dns_manager_set_tunnel_interface_servers(DnsManager *self, std::vector<std::string> servers) {
    std::unique_lock l(self->mutex);

    dbglog(logger, "{}", servers);

    self->tun_interface_servers = {std::make_move_iterator(servers.begin()), std::make_move_iterator(servers.end())};
    engage_notifications(self, DMSK_TUN_INTERFACE);

    auto [system_servers, changed] = prepare_system_servers(self, std::move(self->system_servers));
    self->system_servers = std::move(system_servers);
    if (changed) {
        engage_notifications(self, DMSK_SYSTEM);
    }

    return true;
}

SystemDnsServers dns_manager_get_system_servers(const DnsManager *self) {
    std::unique_lock l(self->mutex);
    return self->system_servers;
}

std::vector<std::string> dns_manager_get_tunnel_interface_servers(const DnsManager *self) {
    std::unique_lock l(self->mutex);
    return {self->tun_interface_servers.begin(), self->tun_interface_servers.end()};
}

DnsChangeSubscriptionId dns_manager_subscribe_servers_change(
        DnsManager *self, VpnEventLoop *event_loop, DnsChangeNotification notification, void *notification_arg) {
    std::unique_lock l(self->mutex);

    DnsChangeSubscriptionId id = self->next_dns_change_subscription_id++;
    self->dns_change_subscriptions.emplace(id,
            DnsChangeSubscription{
                    .event_loop = event_loop,
                    .notification = notification,
                    .notification_arg = notification_arg,
            });
    return id;
}

void dns_manager_unsubscribe_servers_change(DnsManager *self, DnsChangeSubscriptionId subscription_id) {
    std::unique_lock l(self->mutex);
    self->dns_change_subscriptions.erase(subscription_id);
}

} // namespace ag
