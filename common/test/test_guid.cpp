#include <gtest/gtest.h>

#include "vpn/guid_utils.h"

TEST(GuidUtils, Type4) {
    for (int i = 0; i < 10000; ++i) {
        GUID guid = ag::random_guid();
        ASSERT_EQ(0x40, guid.Data3 & 0xf0);
        ASSERT_GE(guid.Data4[0], 0x80);
        ASSERT_LE(guid.Data4[0], 0xbf);
    }
}
