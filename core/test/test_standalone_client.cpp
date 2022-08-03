#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cassert>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>

#include "net/tls.h"
#include "tcpip/tcpip.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#include "event2/bufferevent.h"
#include "event2/event.h"
#include <event2/thread.h>
#include <event2/util.h>

using namespace ag;

typedef enum {
    REGULAR,             // Regular run a single instance until SIGINT
    START_STOP,          // For testing an unlimited number of the same VPN instance restarts
    RECONFIG,            // For testing an unlimited number of VPN reconfigurations (stop running and start new one)
    OUTER_PACKET_SOURCE, // Just like regular but packets are fed to vpn via `vpn_process_client_packets`
} TestType;

static const TestType TEST_TYPE = REGULAR;

typedef enum {
    CM_SOCKS,
    CM_TUN,
} ClientMode;

#define SLEEP_PERIOD_US 10 * 1000 * 1000 // For start-stop and reconfig tests
#define CLIENT_MODE CM_SOCKS
// #define WRITE_PCAP
// #define REDIRECT_ONLY_TCP
// #define FUZZY_ACTION
// #define FUZZY_SETTINGS

void fsystem(const char *fmt, ...);
static bool connect_to_server(Vpn *v, int line);
static void vpn_handler(void *arg, VpnEvent what, void *data);

VpnSettings g_vpn_settings = {{vpn_handler, nullptr}, {}};
VpnUpstreamConfig g_vpn_server_config;
VpnListenerConfig g_vpn_common_listener_config;
VpnSocksListenerConfig g_vpn_socks_listener_config;
VpnTunListenerConfig g_vpn_tun_listener_config;
Vpn *g_vpn;

bool g_stopped = false;
sem_t g_stop_barrier;

bool g_waiting_connect_result = false;
std::optional<bool> g_connect_result;
std::mutex g_connect_result_guard;
std::condition_variable g_connect_barrier;

void setup_netns(const char *ifname) {
    fsystem("ip netns add lwip");
    fsystem("ip link set %s netns lwip", ifname);
}

#define NETNS_PREFIX "ip netns exec lwip "

void setup_if(const char *ifname, int mtu) {
    fsystem(NETNS_PREFIX "ip addr add 1.1.1.1/24 dev %s", ifname);
    fsystem(NETNS_PREFIX "ip -6 addr add fd11::1/64 dev %s", ifname);
    fsystem(NETNS_PREFIX "ip link set dev %s mtu %d up", ifname, mtu);
}

void setup_routes(const char *ifname) {
    fsystem(NETNS_PREFIX "ip ro replace default dev %s", ifname);
    fsystem(NETNS_PREFIX "ip -6 ro replace default dev %s", ifname);
}

#ifdef __linux__
int tun_open(int mtu) {
    evutil_socket_t fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
        perror("open /dev/net/tun");
        exit(1);
    }

    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    char devname[7];
    memset(devname, 0, sizeof(devname));

    errno = 0;
    if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl TUNSETIFF");
        evutil_closesocket(fd);
        exit(1);
    }

    printf("Device %s opened, setting up\n", ifr.ifr_name);

    setup_netns(ifr.ifr_name);
    setup_if(ifr.ifr_name, mtu);
    setup_routes(ifr.ifr_name);
    printf("To run netns session, run: \n\n");
    printf("  \033[1msudo env debian_chroot=' LWIP ' ip netns exec lwip su -p $USER\033[0m\n\n");

    return fd;
}
#else
int tun_open(int mtu) {
    return -1;
}
#endif

void fsystem(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    char cmd[1024];
    vsnprintf(cmd, 1024, fmt, args);
    printf("> %s\n", cmd);
    system(cmd);

    va_end(args);
}

void sighandler(int sig) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    fprintf(stderr, "\n\n\n\n!!!!SIGNAL!!!!\n\n\n\n");

    if (g_vpn != nullptr) {
        switch (TEST_TYPE) {
        case REGULAR:
        case OUTER_PACKET_SOURCE:
            vpn_stop(g_vpn);
            break;
        case START_STOP:
        case RECONFIG:
            // do nothing
            break;
        }

        g_stopped = true;
        if (0 != sem_post(&g_stop_barrier)) {
            printf("Failed to set stop barrier: %s\n", strerror(errno));
            abort();
        }
    } else {
        exit(1);
    }
}

static bool connect_to_server(Vpn *v, int line) {
    std::unique_lock l(g_connect_result_guard);
    g_waiting_connect_result = true;

    VpnConnectParameters parameters = {
            .upstream_config = g_vpn_server_config,
    };
    VpnError err = vpn_connect(v, &parameters);
    if (err.code != 0) {
        printf("Failed to connect to server (line=%d): %s (%d)\n", line, err.text, err.code);
    } else {
        g_connect_barrier.wait(l, []() {
            return g_stopped || g_connect_result.has_value();
        });
    }

    bool result = err.code == VPN_EC_NOERROR && g_connect_result.value_or(false);

    g_waiting_connect_result = false;
    g_connect_result.reset();

    return result;
}

static void vpn_runner() {
    switch (TEST_TYPE) {
    case REGULAR:
        if (!connect_to_server(g_vpn, __LINE__)) {
            vpn_stop(g_vpn);
            return;
        }
        break;
    case START_STOP:
        if (!connect_to_server(g_vpn, __LINE__)) {
            // will be stopped in main loop
            return;
        }
    case OUTER_PACKET_SOURCE:
        // connected already, do nothing
    case RECONFIG:
        // connecting manually in main loop, do nothing
        break;
    }

    VpnListener *listener = nullptr;

    switch (CLIENT_MODE) {
    case CM_TUN:
        if (TEST_TYPE == OUTER_PACKET_SOURCE) {
            g_vpn_tun_listener_config.fd = -1;
        } else {
            g_vpn_tun_listener_config.fd = tun_open(DEFAULT_MTU_SIZE);
        }
        listener = vpn_create_tun_listener(g_vpn, &g_vpn_tun_listener_config);
        break;
    case CM_SOCKS:
        listener = vpn_create_socks_listener(g_vpn, &g_vpn_socks_listener_config);
        break;
    }

    vpn_listen(g_vpn, listener, &g_vpn_common_listener_config);
}

static void vpn_handler(void *arg, VpnEvent what, void *data) {
    switch (what) {
    case VPN_EVENT_PROTECT_SOCKET:
    case VPN_EVENT_ENDPOINT_CONNECTION_STATS:
    case VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE:
        // do nothing
        break;
    case VPN_EVENT_VERIFY_CERTIFICATE: {
        auto *event = (VpnVerifyCertificateEvent *) data;

        const char *err = tls_verify_cert(event->ctx, nullptr);
        if (err == nullptr) {
            printf("Certificate verified successfully\n");
            event->result = 0;
        } else {
            printf("Failed to verify certificate: %s\n", err);
            event->result = -1;
        }
        break;
    }
    case VPN_EVENT_STATE_CHANGED: {
        const VpnStateChangedEvent *event = (VpnStateChangedEvent *) data;
        if (event->state == VPN_SS_WAITING_RECOVERY) {
            printf("Endpoint connection state changed: state=%d to_next=%dms err=%d %s\n", event->state,
                    (int) event->waiting_recovery_info.time_to_next_ms, event->waiting_recovery_info.error.code,
                    event->waiting_recovery_info.error.text);
        } else if (event->state == VPN_SS_CONNECTED) {
            printf("Endpoint connection state changed: state=%d\n", event->state);
        } else {
            printf("Endpoint connection state changed: state=%d err=%d %s\n", event->state, event->error.code,
                    event->error.text);
        }

        std::scoped_lock l(g_connect_result_guard);
        if (g_waiting_connect_result && (event->state == VPN_SS_CONNECTED || event->state == VPN_SS_DISCONNECTED)) {
            g_connect_result = event->state == VPN_SS_CONNECTED;
            g_connect_barrier.notify_one();
        }
        break;
    }
    case VPN_EVENT_CLIENT_OUTPUT: {
        assert(TEST_TYPE == OUTER_PACKET_SOURCE);

        const VpnClientOutputEvent *event = (VpnClientOutputEvent *) data;
        ssize_t written = writev(*(int *) arg, event->packet.chunks, event->packet.chunks_num);
        if (written < 0) {
            printf("%s(): %s\n", __func__, strerror(errno));
            abort();
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

        info.appname = "test";

        vpn_complete_connect_request(g_vpn, &info);
        break;
    }
    }
}

static void regular_test() {
    g_vpn = vpn_open(&g_vpn_settings);
    if (nullptr == g_vpn) {
        abort();
    }

    std::thread worker = std::thread([]() {
        vpn_runner();
    });
    worker.join();

    if (0 != sem_wait(&g_stop_barrier)) {
        printf("Failed to wait for stop barrier: %s\n", strerror(errno));
        abort();
    }

    vpn_close(g_vpn);
}

static void reconfig_test() {
    g_vpn = vpn_open(&g_vpn_settings);
    if (nullptr == g_vpn) {
        abort();
    }

    if (!connect_to_server(g_vpn, __LINE__)) {
        g_stopped = true;
    }

    std::thread worker;
    while (!g_stopped) {
        worker = std::thread([]() {
            vpn_runner();
        });

        usleep(SLEEP_PERIOD_US);

#ifdef FUZZY_SETTINGS
        vpn_settings.routing.mode = !!(rand() % 2) ? VPN_MODE_GENERAL : VPN_MODE_SELECTIVE;
        vpn_settings.quic_enabled = !!(rand() % 2);
#endif

        Vpn *vpn2 = vpn_open(&g_vpn_settings);
        if (nullptr == vpn2) {
            abort();
        }

        if (!connect_to_server(vpn2, __LINE__)) {
            break;
        }

        vpn_stop(g_vpn);

        worker.join();

        vpn_close(g_vpn);

        g_vpn = vpn2;
    }

    worker.join();

    vpn_stop(g_vpn);
    vpn_close(g_vpn);
}

static void start_stop_test() {
    g_vpn = vpn_open(&g_vpn_settings);
    if (nullptr == g_vpn) {
        abort();
    }

    std::thread worker;
    while (!g_stopped) {
        worker = std::thread([]() {
            vpn_runner();
        });

        usleep(SLEEP_PERIOD_US);

        vpn_stop(g_vpn);
        worker.join();
    }

    vpn_close(g_vpn);
}

static void tun_event_callback(evutil_socket_t fd, short ev_flag, void *arg) {
    ssize_t bytes_read = read(fd, arg, DEFAULT_MTU_SIZE);
    if (bytes_read < 0) {
        printf("%s(): %s\n", __func__, strerror(errno));
        abort();
    }

    iovec packet = {arg, (size_t) bytes_read};
    VpnPackets packets = {&packet, 1};
    vpn_process_client_packets(g_vpn, packets);
}

static void *tun_runner(void *arg) {
    auto *ev_base = (event_base *) arg;
    event_base_dispatch(ev_base);

    return nullptr;
}

static void tun_runner_stop_cb(evutil_socket_t fd, short what, void *arg) {
    auto *ev_base = (event_base *) arg;
    event_base_loopexit(ev_base, nullptr);
}

static int g_tun_fd = -1;

static void outer_packet_source_test() {
    g_tun_fd = tun_open(DEFAULT_MTU_SIZE);
    g_vpn_settings.handler.arg = &g_tun_fd;

    g_vpn = vpn_open(&g_vpn_settings);
    if (nullptr == g_vpn) {
        abort();
    }

    auto *tun_buffer = (uint8_t *) malloc(DEFAULT_MTU_SIZE);

    struct event_base *ev_base = event_base_new();
    struct event *ev = event_new(ev_base, g_tun_fd, EV_READ | EV_PERSIST, tun_event_callback, tun_buffer);
    event_add(ev, nullptr);

    if (!connect_to_server(g_vpn, __LINE__)) {
        abort();
    }

    std::thread vpn_worker = std::thread([]() {
        vpn_runner();
    });
    std::thread tun_worker = std::thread([ev_base]() {
        tun_runner(ev_base);
    });
    vpn_worker.join();

    event_base_once(ev_base, -1, EV_TIMEOUT, tun_runner_stop_cb, ev_base, nullptr);

    tun_worker.join();

    vpn_close(g_vpn);

    event_free(ev);
    event_base_free(ev_base);

    free(tun_buffer);
    evutil_closesocket(g_tun_fd);
}

int main(int argc, char **argv) {
    srand(time(nullptr));

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);
    struct sigaction act = {SIG_IGN};
    sigaction(SIGPIPE, &act, nullptr);

    if (0 != sem_init(&g_stop_barrier, 0, 0)) {
        printf("Failed to init stop barrier: %s\n", strerror(errno));
        abort();
    }

    ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);

    g_vpn_settings.mode = VPN_MODE_GENERAL;
    g_vpn_settings.exclusions = VPNSTR_INIT("example.org");
    // vpn_settings.quic_enabled = true;
    g_vpn_settings.killswitch_enabled = true;

    VpnEndpoint endpoints[] = {
            {sockaddr_from_str("192.168.11.22:7777"), "localhost"},
    };
    g_vpn_server_config.location = (VpnLocation){"1", {endpoints, std::size(endpoints)}};
    g_vpn_server_config.username = "premium";
    g_vpn_server_config.password = "premium";

    switch (CLIENT_MODE) {
    case CM_TUN:
        // vpn_common_listener_config.tun.mtu_size = DEFAULT_MTU_SIZE;
#ifdef WRITE_PCAP
        vpn_common_listener_config.tun.pcap_filename = "tun.pcap";
#endif /* WRITE_PCAP */
        break;
    case CM_SOCKS: {
        switch (TEST_TYPE) {
        case REGULAR:
        case START_STOP: {
            g_vpn_socks_listener_config.listen_address = sockaddr_from_str("192.168.10.168:8888");
            g_vpn_socks_listener_config.username = "1";
            g_vpn_socks_listener_config.password = "1";
            break;
        }
        case RECONFIG:
            break;
        }
        break;
    }
    }

    // vpn_common_listener_config.timeout_ms = 20000;

    typedef void (*TestFunc)(void);
    static const TestFunc TEST_TABLE[] = {
            [REGULAR] = regular_test,
            [RECONFIG] = reconfig_test,
            [START_STOP] = start_stop_test,
            [OUTER_PACKET_SOURCE] = outer_packet_source_test,
    };

    TEST_TABLE[TEST_TYPE]();

    return 0;
}
