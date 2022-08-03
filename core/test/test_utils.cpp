#include <string>
#include <vector>

#include <FFOS/dir.h>
#include <FFOS/file.h>
#include <gtest/gtest.h>

#include "vpn/internal/utils.h"

using namespace ag;

class TunnelAddressTest : public testing::TestWithParam<std::pair<TunnelAddress, TunnelAddress>> {
protected:
    void SetUp() override {
        const auto &param = GetParam();
        ASSERT_EQ(std::get_if<std::monostate>(&param.first), nullptr);
        ASSERT_EQ(std::get_if<std::monostate>(&param.second), nullptr);
    }
};

class Equal : public TunnelAddressTest {};
TEST_P(Equal, Test) {
    const auto &param = GetParam();
    ASSERT_EQ(param.first, param.second);
}

static const std::pair<TunnelAddress, TunnelAddress> EQUAL_ADDRS_SAMPLES[] = {
        {NamePort{"example.org", 80}, NamePort{"example.org", 80}},
        {sockaddr_from_str("1.1.1.1:1"), sockaddr_from_str("1.1.1.1:1")},
        {sockaddr_from_str("1.1.1.1"), sockaddr_from_str("1.1.1.1")},
        {sockaddr_from_str("[::1]:1"), sockaddr_from_str("[::1]:1")},
        {sockaddr_from_str("::1"), sockaddr_from_str("::1")},
};
INSTANTIATE_TEST_SUITE_P(TunnelAddress, Equal, testing::ValuesIn(EQUAL_ADDRS_SAMPLES));

class NotEqual : public TunnelAddressTest {};
TEST_P(NotEqual, Test) {
    const auto &param = GetParam();
    ASSERT_NE(param.first, param.second);
}

static const std::pair<TunnelAddress, TunnelAddress> NOT_EQUAL_ADDRS_SAMPLES[] = {
        {NamePort{"example.org", 80}, NamePort{"example.org", 0}},
        {NamePort{"example.org", 80}, NamePort{"example.com", 80}},
        {NamePort{"example.org", 80}, NamePort{"Example.org", 80}},
        {sockaddr_from_str("1.1.1.1:1"), sockaddr_from_str("1.1.1.1:0")},
        {sockaddr_from_str("1.1.1.1:1"), sockaddr_from_str("1.1.1.11:1")},
        {sockaddr_from_str("[::1]:1"), sockaddr_from_str("[::1]:11")},
        {sockaddr_from_str("[::1]:1"), sockaddr_from_str("[::2]:1")},
        {sockaddr_from_str("::1"), sockaddr_from_str("::2")},
};
INSTANTIATE_TEST_SUITE_P(TunnelAddressTest, NotEqual, testing::ValuesIn(NOT_EQUAL_ADDRS_SAMPLES));

TEST(CleanUpFiles, NonExistingDirectory) {
    ASSERT_FALSE(fffile_exists("./hopefully_nonexisting_dir"));
    // just check it does not crash
    clean_up_buffer_files("./hopefully_nonexisting_dir");
}

static void create_buffer_file(const std::string &dir, const std::string &name) {
    fffd fd = fffile_open((dir + "/" + name).c_str(), FFO_CREATE);
    ASSERT_NE(fd, FF_BADFD) << fferr_strp(fferr_last());
    fffile_close(fd);
}

static void rmdir_r(const char *dir) {
    char path[FF_MAXPATH];
    strcpy(path, dir);
    ffdirentry dent = {};
    ffdir d = ffdir_open(path, sizeof(path), &dent);

    while (0 == ffdir_read(d, &dent)) {
        std::string en = safe_path_name(ffdir_entryname(&dent));
        if (en == "." || en == "..") {
            continue;
        }

        std::string fn = std::string(dir) + "/" + en;
        if (fffile_isdir(fffile_infoattr(ffdir_entryinfo(&dent)))) {
            rmdir_r(fn.c_str());
        } else {
            fffile_rm(fn.c_str());
        }
    }

    ffdir_close(d);
    ffdir_rm(dir);
}

TEST(CleanUpFiles, Test) {
    const std::string dir = "./hopefully_nonexisting_dir";
    ASSERT_FALSE(fffile_exists(dir.c_str()));
    ASSERT_EQ(0, ffdir_make(dir.c_str())) << fferr_strp(fferr_last());

    std::vector<std::string> file_names;
    for (uint64_t i = 0; i < 10; ++i) {
        file_names.emplace_back(str_format(CONN_BUFFER_FILE_NAME_FMT, i, i + 1));
    }

    // using EXPECT_* just to let it get to the end and remove temporary test files
    for (const std::string &fn : file_names) {
        EXPECT_NO_FATAL_FAILURE(create_buffer_file(dir, fn));
    }

    clean_up_buffer_files(dir.c_str());

    for (const std::string &fn : file_names) {
        EXPECT_FALSE(fffile_exists((dir + "/" + fn).c_str()));
    }

    rmdir_r(dir.c_str());
}
