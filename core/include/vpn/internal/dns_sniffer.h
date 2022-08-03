#pragma once

#include "common/logger.h"
#include "vpn/internal/domain_filter.h"
#include "vpn/utils.h"

namespace ag {

struct DnsSnifferParameters {
    /// Needed to store IP addresses which potentially target the excluded hosts
    DomainFilter *filter = nullptr;
};

class DnsSniffer {
public:
    DnsSniffer() = default;
    ~DnsSniffer() = default;

    DnsSniffer(const DnsSniffer &) = delete;
    DnsSniffer &operator=(const DnsSniffer &) = delete;
    DnsSniffer(DnsSniffer &&) = delete;
    DnsSniffer &operator=(DnsSniffer &&) = delete;

    void init(const DnsSnifferParameters &parameters);

    /**
     * Process an intercepted DNS reply.
     * @param data UDP payload.
     * @param library_request Must be `true` if the request was made by this library.
     */
    void on_intercepted_dns_reply(U8View data, bool library_request);

private:
    DnsSnifferParameters m_parameters = {};
    ag::Logger m_log{"DNS_SNIFFER"};
};

} // namespace ag
