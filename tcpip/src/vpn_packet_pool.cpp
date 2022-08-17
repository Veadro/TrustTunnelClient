#include "vpn_packet_pool.h"

namespace ag {

VpnPacketPool::VpnPacketPool(size_t size, int mtu) : m_capacity(size), m_mtu(mtu) {
    for (size_t i = 0; i < size; ++i) {
        m_packets.emplace_back(new uint8_t[m_mtu]);
    }
}

VpnPacket VpnPacketPool::get_packet() {
    auto destructor = [](void *arg, uint8_t* data) {
        auto *pool = (VpnPacketPool *) arg;
        pool->return_packet_data(data);
    };
    if (m_packets.empty()) {
        return VpnPacket{
                .data = new uint8_t[m_mtu],
                .destructor = destructor,
                .destructor_arg = this
        };
    } else {
        VpnPacket packet{
                .data = m_packets.front().release(),
                .destructor = destructor,
                .destructor_arg = this
        };
        m_packets.pop_front();
        return packet;
    }
}

void VpnPacketPool::return_packet_data(uint8_t *packet) {
    std::unique_ptr<uint8_t[]> data{packet};
    if (m_packets.size() < m_capacity) {
        m_packets.emplace_back(std::move(data));
    }
}

int VpnPacketPool::get_size() {
    return m_packets.size();
}

} // namespace ag
