#include "vpn/internal/dns_sniffer.h"

#include "net/dns_utils.h"
#include "vpn/internal/tunnel.h"

#define log_sniffer(p_, lvl_, fmt_, ...) lvl_##log((p_)->m_log, fmt_, ##__VA_ARGS__)

namespace ag {

void DnsSniffer::init(const DnsSnifferParameters &p) {
    m_parameters = p;
}

void DnsSniffer::on_intercepted_dns_reply(U8View data, bool library_request) {
    dns_utils::DecodeResult r = dns_utils::decode_packet(data);
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_sniffer(this, trace, "Failed to parse reply: {}", e->description);
        return;
    }

    const auto *answer = std::get_if<dns_utils::DecodedReply>(&r);
    if (answer == nullptr) {
        return;
    }

    bool found_exclusion = false;
    for (const std::string &name : answer->names) {
        found_exclusion = DFMS_EXCLUSION == m_parameters.filter->match_domain(name);
        if (found_exclusion) {
            log_sniffer(this, dbg, "Domain name ({}) is excluded, adding its addresses as suspects", name);
            break;
        }
    }

    if (found_exclusion) {
        for (const dns_utils::AnswerAddress &addr : answer->addresses) {
            m_parameters.filter->add_exclusion_suspect(sockaddr_from_raw(addr.ip.data(), addr.ip.size(), 0),
                    library_request ? std::max(addr.ttl, Tunnel::EXCLUSIONS_RESOLVE_PERIOD) : addr.ttl);
        }
    }
}

} // namespace ag
