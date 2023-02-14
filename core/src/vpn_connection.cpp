#include "vpn/internal/vpn_connection.h"
#include "net/dns_utils.h"

namespace ag {

VpnConnection *VpnConnection::make(uint64_t client_id, TunnelAddressPair addr, int proto) {
    VpnConnection *self; // NOLINT(cppcoreguidelines-init-variables)
    if (proto == IPPROTO_TCP) {
        self = new TcpVpnConnection{};
    } else {
        assert(proto == IPPROTO_UDP);
        self = new UdpVpnConnection{};
    }

    self->client_id = client_id;
    self->addr = std::move(addr);
    self->proto = proto;

    const sockaddr *dst = (sockaddr *) std::get_if<sockaddr_storage>(&self->addr.dst);
    self->flags.set(
            CONNF_PLAIN_DNS_CONNECTION, dst != nullptr && dns_utils::PLAIN_DNS_PORT_NUMBER == sockaddr_get_port(dst));

    return self;
}

SockAddrTag VpnConnection::make_tag() const {
    const sockaddr_storage *dst = std::get_if<sockaddr_storage>(&this->addr.dst);
    return {(dst != nullptr) ? *dst : sockaddr_storage{}, this->app_name};
}

} // namespace ag
