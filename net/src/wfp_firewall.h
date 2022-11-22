#pragma once

#include <memory>
#include <string_view>

#include "common/error.h"
#include "vpn/utils.h"

namespace ag {

enum WfpFirewallErrorCode {
    FE_NOT_INITIALIZED,
    FE_WFP_ERROR,
};

template <>
struct ErrorCodeToString<WfpFirewallErrorCode> {
    std::string operator()(WfpFirewallErrorCode e) {
        switch (e) {
        case FE_NOT_INITIALIZED:
            return "The firewall failed to initialize";
        case FE_WFP_ERROR:
            return "A WFP function failed";
        }
    }
};

using WfpFirewallError = Error<WfpFirewallErrorCode>;

/** WFP-based firewall. */
class WfpFirewall {
public:
    WfpFirewall();
    ~WfpFirewall();

    WfpFirewall(const WfpFirewall &) = delete;
    WfpFirewall &operator=(const WfpFirewall &) = delete;

    WfpFirewall(WfpFirewall &&) = default;
    WfpFirewall &operator=(WfpFirewall &&) = default;

    /** Block DNS traffic to/from all addresses except `allowed`. */
    WfpFirewallError restrict_dns_to(std::basic_string_view<sockaddr *> allowed);

    /** Block all inbound/outbound IPv6 traffic. */
    WfpFirewallError block_ipv6();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ag
