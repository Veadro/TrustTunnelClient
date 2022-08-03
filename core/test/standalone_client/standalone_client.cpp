#ifdef __APPLE__
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#endif // __APPLE__

#ifdef __linux__
#include <net/if.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#include <sys/ioctl.h>

#include <atomic>
#include <csignal>
#include <fstream>
#include <unordered_map>

#define CXXOPTS_NO_RTTI
#include <cxxopts.hpp>
#include <magic_enum.hpp>
#include <nlohmann/json.hpp>

#include "common/cidr_range.h"
#include "common/file.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "net/tls.h"
#include "vpn/vpn.h"

#define SLEEP() sleep(100000)

#define DEFAULT_MTU_SIZE 1500u
#define DEFAULT_IPV4_ROUTE "0.0.0.0/0"
#define DEFAULT_IPV6_ROUTE "::/0"
#define DEFAULT_IPV6_ROUTE_UNICAST "2000::/3"
#define DEFAULT_CONFIG_FILE "standalone_client.conf"

using namespace ag;

static bool connect_to_server(Vpn *v, int line);
static void vpn_handler(void *arg, VpnEvent what, void *data);

static ag::Logger g_logger("STANDALONE_CLIENT");

static const std::unordered_map<std::string, ag::LogLevel> LOG_LEVEL_MAP = {
        {"error", ag::LOG_LEVEL_ERROR},
        {"warn", ag::LOG_LEVEL_WARN},
        {"info", ag::LOG_LEVEL_INFO},
        {"debug", ag::LOG_LEVEL_DEBUG},
        {"trace", ag::LOG_LEVEL_TRACE},
};

enum ListenerType {
    LT_TUN,
    LT_SOCKS,
};

static const std::unordered_map<std::string, ListenerType> LISTENER_TYPE_MAP = {
        {"tun", LT_TUN},
        {"socks", LT_SOCKS},
};

static cxxopts::Options g_options("Standalone client", "Simple macOS/Linux console client");

static std::optional<std::string> read_file_to_str(const std::string &filename) {
    std::string file_str;

    auto file = ag::file::open(filename, ag::file::RDONLY);
    if (file < 0) {
        errlog(g_logger, "Cannot open file: {}", strerror(errno));
        return std::nullopt;
    }
    size_t size = ag::file::get_size(file);
    file_str.resize(size);
    auto read_size = ag::file::read(file, file_str.data(), size);

    if (read_size == 0) {
        errlog(g_logger, "Cannot read data from file: {}", strerror(errno));
        return std::nullopt;
    }
    ag::file::close(file);
    return file_str;
}

static void split_default_route(std::vector<ag::CidrRange> &routes, std::string_view route) {
    for (auto idx = 0; idx < routes.size(); ++idx) {
        if (routes[idx].to_string() == route) {
            routes.erase(routes.begin() + idx);

            auto splitted = ag::CidrRange(route).split();
            routes.push_back(splitted.value().first);
            routes.push_back(splitted.value().second);
        }
    }
}

struct Params {
    std::string hostname;
    std::string address;
    std::string username;
    std::string password;
    std::string listener_pass;
    std::string listener_username;
    std::string listener_address;
    ag::LogLevel loglevel = ag::LOG_LEVEL_INFO;
    ListenerType listener_type = LT_SOCKS;
    bool skip_verify = false;
    uint32_t mtu_size = DEFAULT_MTU_SIZE;
    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    std::string dns_upstream;

    void init(cxxopts::ParseResult &result, const std::string &config) {
        parse_json_config(config);
        parse_args(result);
    }

    void parse_args(cxxopts::ParseResult &result) {
        if (result.count("s") > 0) {
            skip_verify = result["s"].as<bool>();
        }
        if (result.count("loglevel") > 0) {
            set_loglevel(result["loglevel"].as<std::string>());
        }
    }

    void parse_listener_info(nlohmann::json::reference &listener_info) {
        listener_username = listener_info["socks_user"];
        listener_pass = listener_info["socks_pass"];
        std::string host = listener_info["socks_host"];
        if (listener_username.empty() && listener_pass.empty()) {
            host = "127.0.0.1";
        }
        std::string port = listener_info["socks_port"];
        listener_address = host + ":" + port;
    }

    void parse_server_info(nlohmann::json::reference &server_info) {
        hostname = server_info["hostname"];
        address = server_info["address"];
        username = server_info["username"];
        password = server_info["password"];
    }

    void parse_routes(nlohmann::json::reference &included_routes, nlohmann::json::reference &excluded_routes) {
        for (std::string included_route : included_routes) {
            if (included_route.find(':') == std::string::npos) {
                ipv4_routes.emplace_back(included_route);
            } else {
                if (included_route == DEFAULT_IPV6_ROUTE) {
                    ipv6_routes.emplace_back(DEFAULT_IPV6_ROUTE_UNICAST);
                } else {
                    ipv6_routes.emplace_back(included_route);
                }
            }
        }

        auto [host_view, port_view] = ag::utils::split_host_port(address);
        ipv4_routes = ag::CidrRange::exclude(ipv4_routes, ag::CidrRange(host_view));
        ipv6_routes = ag::CidrRange::exclude(ipv6_routes, ag::CidrRange(host_view));

        for (std::string excluded_route : excluded_routes) {
            if (excluded_route.find(':') == std::string::npos) {
                ipv4_routes = ag::CidrRange::exclude(ipv4_routes, ag::CidrRange(excluded_route));
            } else {
                ipv6_routes = ag::CidrRange::exclude(ipv6_routes, ag::CidrRange(excluded_route));
            }
        }

        split_default_route(ipv4_routes, DEFAULT_IPV4_ROUTE);
        split_default_route(ipv6_routes, DEFAULT_IPV6_ROUTE_UNICAST);
    }

    void parse_json_config(const std::string &config) {
        nlohmann::json config_file = nlohmann::json::parse(config);

        parse_server_info(config_file["server_info"]);

        skip_verify = config_file["server_info"]["skip_cert_verify"];

        if (auto it = LISTENER_TYPE_MAP.find(config_file["listener_type"]); it != LISTENER_TYPE_MAP.end()) {
            listener_type = it->second;
        } else {
            errlog(g_logger, "Unknown listener type, pass --help to see possible values");
            exit(1);
        }

        if (listener_type == LT_TUN) {
            auto tun_info = config_file["tun_info"];
            mtu_size = tun_info["mtu_size"];
            parse_routes(tun_info["included_routes"], tun_info["excluded_routes"]);
        } else if (listener_type == LT_SOCKS) {
            parse_listener_info(config_file["socks_info"]);
        }

        set_loglevel(config_file["loglevel"]);

        if (config_file.contains("dns_upstream")) {
            dns_upstream = config_file["dns_upstream"];
        }
    }

    void set_loglevel(const std::string &loglevel_str) {
        if (auto it = LOG_LEVEL_MAP.find(loglevel_str); it != LOG_LEVEL_MAP.end()) {
            loglevel = it->second;
        } else {
            errlog(g_logger, "Unknown logger type, pass --help to see possible values");
            exit(1);
        }
    }
};

struct TunInfo {
    int fd = -1;
    uint32_t tun_num = 0;
    std::string name;
};

static VpnSettings g_vpn_settings = {{vpn_handler, nullptr}, {}};
static VpnUpstreamConfig g_vpn_server_config;
static VpnListenerConfig g_vpn_common_listener_config;
static VpnTunListenerConfig g_vpn_tun_listener_config;
static VpnSocksListenerConfig g_vpn_socks_listener_config;
static Vpn *g_vpn;
static TunInfo g_tun_info;
static Params g_params;

static bool g_waiting_connect_result = false;
static std::optional<bool> g_connect_result;
static std::mutex g_connect_result_guard;
static std::condition_variable g_connect_barrier;
static std::atomic_bool g_stop = false;

static void sighandler(int sig) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (g_vpn != nullptr) {
        g_stop = true;
    } else {
        exit(1);
    }
}

static void fsystem(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    char cmd[1024];
    vsnprintf(cmd, 1024, fmt, args);
    infolog(g_logger, "{} {}", geteuid() == 0 ? "#" : "$", safe_to_string_view(cmd));
    system(cmd);

    va_end(args);
}

static void setup_if(const TunInfo &info) {
#ifdef __APPLE__
    fsystem("set -x\n");
    fsystem("/sbin/ifconfig %s mtu %d up", info.name.c_str(), g_params.mtu_size);
    std::string ipv4address = AG_FMT("172.16.218.{}", info.tun_num + 2);
    std::string ipv6address = AG_FMT("fd00::{:x}", info.tun_num + 2);
    fsystem("/sbin/ifconfig %s inet add %s %s netmask 0xffffffff\n", info.name.c_str(), ipv4address.c_str(),
            ipv4address.c_str());
    fsystem("/sbin/ifconfig %s inet6 add %s prefixlen 64\n", info.name.c_str(), ipv6address.c_str());
#endif // __APPLE__
#ifdef __linux__
    std::string ipv4address = AG_FMT("172.16.218.{}", info.tun_num);
    std::string ipv6address = AG_FMT("fd00::{:x}", info.tun_num);
    fsystem("ip addr add %s dev %s", ipv4address.c_str(), info.name.c_str());
    fsystem("ip -6 addr add %s dev %s", ipv6address.c_str(), info.name.c_str());
    fsystem("ip link set dev %s mtu %d up", info.name.c_str(), g_params.mtu_size);
#endif // __linux__
}

static void setup_routes(const TunInfo &info) {
#ifdef __APPLE__
    for (auto &route : g_params.ipv4_routes) {
        fsystem("route add %s -iface %s", route.to_string().c_str(), info.name.c_str());
    }
    for (auto &route : g_params.ipv6_routes) {
        fsystem("route add -inet6 %s -iface %s", route.to_string().c_str(), info.name.c_str());
    }
#endif // __APPLE__
#ifdef __linux__
    for (auto &route : g_params.ipv4_routes) {
        fsystem("ip ro add %s dev %s", route.to_string().c_str(), info.name.c_str());
    }
    for (auto &route : g_params.ipv6_routes) {
        fsystem("ip -6 ro add %s dev %s", route.to_string().c_str(), info.name.c_str());
    }
#endif // __linux__
}

#ifdef __APPLE__
static int tun_open(uint32_t num) {
    int fd;
    struct sockaddr_ctl addr;
    struct ctl_info info;

    if (fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL); fd < 0) {
        errlog(g_logger, "Failed to create socket: {}", strerror(errno));
        return -1;
    }
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));

    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        errlog(g_logger, "IOCTL system call failed: {}", strerror(errno));
        close(fd);
        return -1;
    }

    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = num + 1;

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        errlog(g_logger, "Failed to connect: {}", strerror(errno));
        close(fd);
        return -1;
    }

    g_tun_info = {fd, num, AG_FMT("utun{}", num)};
    infolog(g_logger, "Device {} opened\n", safe_to_string_view(info.ctl_name));

    setup_if(g_tun_info);

    return fd;
#endif // __APPLE__
#ifdef __linux__
    static int tun_open() {
        evutil_socket_t fd;

        if (fd = open("/dev/net/tun", O_RDWR); fd == -1) {
            errlog(g_logger, "Failed to open /dev/net/tun: {}", strerror(errno));
            return -1;
        }

        struct ifreq ifr = {};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        char devname[7];
        memset(devname, 0, sizeof(devname));

        if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
            errlog(g_logger, "ioctl TUNSETIFF failed: {}", strerror(errno));
            evutil_closesocket(fd);
            return -1;
        }
        g_tun_info = {fd, if_nametoindex(ifr.ifr_name), ifr.ifr_name};

        infolog(g_logger, "Device {} opened, setting up\n", ifr.ifr_name);

        setup_if(g_tun_info);

        return fd;
#else
return -1;
#endif // __linux__
    }

    static int create_tunnel() {
#ifdef __APPLE__
        for (uint8_t i = 0; i < 255; i++) {
            if (int fd = tun_open(i); fd != -1) {
                return fd;
            }
        }
#endif // __APPLE__
#ifdef __linux__
        if (int fd = tun_open(); fd != -1) {
            return fd;
        }
#endif //__linux__
        return -1;
    }

    static bool connect_to_server(Vpn * v, int line) {
        std::unique_lock l(g_connect_result_guard);
        g_waiting_connect_result = true;

        VpnConnectParameters parameters = {
                .upstream_config = g_vpn_server_config,
        };
        VpnError err = vpn_connect(v, &parameters);
        if (err.code != 0) {
            errlog(g_logger, "Failed to connect to server (line={}): {} ({})\n", line, safe_to_string_view(err.text),
                    err.code);
        } else {
            g_connect_barrier.wait(l, []() {
                return g_stop || g_connect_result.has_value();
            });
        }

        bool result = err.code == VPN_EC_NOERROR && g_connect_result.value_or(false);

        g_waiting_connect_result = false;
        g_connect_result.reset();

        return result;
    }

    static void vpn_runner(ListenerType type) {
        if (!connect_to_server(g_vpn, __LINE__)) {
            vpn_stop(g_vpn);
            return;
        }

        VpnListener *listener;

        switch (type) {
        case LT_TUN:
            setup_routes(g_tun_info);
            listener = vpn_create_tun_listener(g_vpn, &g_vpn_tun_listener_config);
        case LT_SOCKS:
            listener = vpn_create_socks_listener(g_vpn, &g_vpn_socks_listener_config);
            break;
        default:
            assert(0);
        }

        assert(listener != nullptr);

        auto error = vpn_listen(g_vpn, listener, &g_vpn_common_listener_config);
        if (error.code != 0) {
            errlog(g_logger, "Failed on start listening: {} ({})", safe_to_string_view(error.text),
                    magic_enum::enum_name((VpnErrorCode) error.code));
            close(g_tun_info.fd);
            g_stop = true;
        }
    }

    static void listener_runner(ListenerType listener_type) {
        g_vpn = vpn_open(&g_vpn_settings);
        if (g_vpn == nullptr) {
            abort();
        }

        vpn_runner(listener_type);

        while (!g_stop) {
            SLEEP();
        }

        vpn_stop(g_vpn);
        vpn_close(g_vpn);
    }

    static void vpn_handler(void *, VpnEvent what, void *data) {
        switch (what) {
        case VPN_EVENT_CLIENT_OUTPUT:
        case VPN_EVENT_PROTECT_SOCKET:
        case VPN_EVENT_ENDPOINT_CONNECTION_STATS:
        case VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE:
            // do nothing
            break;
        case VPN_EVENT_VERIFY_CERTIFICATE: {
            auto *event = (VpnVerifyCertificateEvent *) data;
            const char *err = g_params.skip_verify ? nullptr : tls_verify_cert(event->ctx, nullptr);
            if (err == nullptr) {
                tracelog(g_logger, "Certificate verified successfully\n");
                event->result = 0;
            } else {
                errlog(g_logger, "Failed to verify certificate: {}\n", err);
                event->result = -1;
            }
            break;
        }
        case VPN_EVENT_STATE_CHANGED: {
            const VpnStateChangedEvent *event = (VpnStateChangedEvent *) data;
            if (event->state == VPN_SS_WAITING_RECOVERY) {
                tracelog(g_logger, "Endpoint connection state changed: state={} to_next={}ms err={} {}\n", event->state,
                        (int) event->waiting_recovery_info.time_to_next_ms, event->waiting_recovery_info.error.code,
                        safe_to_string_view(event->waiting_recovery_info.error.text));
            } else if (event->error.code != 0 && event->state != VPN_SS_CONNECTED) {
                tracelog(g_logger, "Endpoint connection state changed: state={} err={} {}\n", event->state,
                        event->error.code, safe_to_string_view(event->error.text));
            }

            std::scoped_lock l(g_connect_result_guard);
            if (g_waiting_connect_result && (event->state == VPN_SS_CONNECTED || event->state == VPN_SS_DISCONNECTED)) {
                g_connect_result = event->state == VPN_SS_CONNECTED;
                g_connect_barrier.notify_one();
            }
            break;
        }
        case VPN_EVENT_CONNECT_REQUEST: {
            const VpnConnectRequestEvent *event = (VpnConnectRequestEvent *) data;

            VpnConnectionInfo info = {event->id};
#ifndef REDIRECT_ONLY_TCP
            info.action = VPN_CA_DEFAULT;
#else
        info.action = (event->proto == IPPROTO_TCP) ? VPN_CA_DEFAULT : VPN_CA_FORCE_BYPASS;
#endif

#ifdef FUZZY_ACTION
            info.action = rand() % (VPN_CA_FORCE_REDIRECT + 1);
#endif

            info.appname = "standalone_client";

            vpn_complete_connect_request(g_vpn, &info);
            break;
        }
        }
    }

    static std::string get_config(const std::string &filename) {
        auto file_str = read_file_to_str(filename);
        if (file_str.has_value()) {
            return file_str.value();
        }
        errlog(g_logger, "Cannot parse config file");
        exit(1);
    }

    int main(int argc, char **argv) {
        srand(time(nullptr));
        signal(SIGINT, sighandler);
        signal(SIGTERM, sighandler);
        signal(SIGPIPE, SIG_IGN);
        struct sigaction act = {SIG_IGN};
        sigaction(SIGPIPE, &act, nullptr);

        g_options.add_options()("s", "Skip verify certificate", cxxopts::value<bool>()->default_value("false"))(
                "c,config", "Config file name.", cxxopts::value<std::string>()->default_value(DEFAULT_CONFIG_FILE))(
                "l,loglevel", "Logging level. Possible values: error, warn, info, debug, trace.",
                cxxopts::value<std::string>()->default_value("info"))("help", "Print usage");

        auto result = g_options.parse(argc, argv);
        if (result.count("help")) {
            std::cout << g_options.help() << std::endl;
            exit(0);
        }
        auto filename = result["config"].as<std::string>();
        g_params.init(result, get_config(filename));

        ag::Logger::set_log_level(g_params.loglevel);

        g_vpn_settings.killswitch_enabled = true;
        VpnEndpoint endpoints[] = {
                {sockaddr_from_str(g_params.address.c_str()), g_params.hostname.c_str()},
        };
        g_vpn_server_config.location = (VpnLocation){"1", {endpoints, std::size(endpoints)}};
        g_vpn_server_config.username = g_params.username.c_str();
        g_vpn_server_config.password = g_params.password.c_str();

        switch (g_params.listener_type) {
        case LT_TUN:
            if (create_tunnel() < 0) {
                errlog(g_logger, "Failed to create tunnel");
                exit(1);
            } else {
                g_vpn_tun_listener_config.fd = g_tun_info.fd;
                g_vpn_tun_listener_config.mtu_size = g_params.mtu_size;
            }
            break;
        case LT_SOCKS:
            g_vpn_socks_listener_config.listen_address = sockaddr_from_str(g_params.listener_address.c_str());
            g_vpn_socks_listener_config.username = g_params.listener_username.c_str();
            g_vpn_socks_listener_config.password = g_params.listener_pass.c_str();
            break;
        default:
            assert(0);
        }

        if (!g_params.dns_upstream.empty()) {
            g_vpn_common_listener_config.dns_upstream = g_params.dns_upstream.c_str();
        }

        listener_runner(g_params.listener_type);

        return 0;
    }
