#include <gtest/gtest.h>

#include "net/utils.h"

using namespace ag;

#ifdef _WIN32

TEST(NetUtils, RetrieveSystemDnsServers) {
    uint32_t iface = vpn_win_detect_active_if();
    ASSERT_NE(iface, 0);

    auto result = retrieve_interface_dns_servers(iface);
    ASSERT_FALSE(result.has_error()) << result.error()->str();
}

#endif // _WIN32
