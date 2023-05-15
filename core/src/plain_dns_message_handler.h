#pragma once

#include <variant>

#include "common/logger.h"
#include "vpn/internal/utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/vpn_dns_resolver.h"
#include "vpn/utils.h"

namespace ag {

class PlainDnsMessageHandler {
public:
    struct Parameters {
        VpnClient *vpn = nullptr;
        const VpnDnsResolver *dns_resolver = nullptr;
    };

    enum RoutingPolicy {
        /**
         * A query should be routed according to the default routing policy, i.e. like
         * a connection to a domain NOT from the exclusion list (see `VpnMode`)
         */
        RP_DEFAULT,
        /**
         * A query should be routed in the exceptional manner, i.e. like a connection to
         * a domain from the exclusion list (see `VpnMode`)
         */
        RP_EXCEPTIONAL,
        /** A query should be routed through the set up DNS proxy */
        RP_THROUGH_DNS_PROXY,
        /** A query should be dropped */
        RP_DROP,
        /** A query should be routed to the target target host directly unconditionally */
        RP_FORCE_BYPASS,
    };

    PlainDnsMessageHandler() = default;
    ~PlainDnsMessageHandler() = default;

    PlainDnsMessageHandler(const PlainDnsMessageHandler &) = delete;
    PlainDnsMessageHandler &operator=(const PlainDnsMessageHandler &) = delete;
    PlainDnsMessageHandler(PlainDnsMessageHandler &&) = delete;
    PlainDnsMessageHandler &operator=(PlainDnsMessageHandler &&) = delete;

    void init(const Parameters &parameters);

    /**
     * Checks if the domain being resolved should be routed through endpoint.
     * In case it should and user set up a custom DNS resolver, the message
     * will be routed through the DNS proxy.
     * @param data DNS message.
     * @return See `RoutingPolicy`.
     */
    [[nodiscard]] RoutingPolicy on_outgoing_message(U8View data) const;

    /**
     * Process an intercepted DNS reply.
     * @param data DNS message.
     * @param library_request Must be `true` if the request was made by this library.
     */
    void on_incoming_message(U8View data, bool library_request);

    /**
     * Get the routing policy corresponding to the vpn mode
     */
    [[nodiscard]] static RoutingPolicy vpn_action_to_routing_policy(VpnMode mode, VpnConnectAction action);

private:
    Parameters m_parameters = {};
    ag::Logger m_log{"DNS_MSG_HANDLER"};
};

} // namespace ag
