#pragma once

#include <event2/buffer.h>
#include <span>

#ifdef _WIN32
#include "wintun.h"
#else
#define HMODULE void *
#endif

#include "vpn/platform.h"
#include "vpn/utils.h"
#include <common/cidr_range.h>
#include <common/net_utils.h>

#ifdef __cplusplus
namespace ag {
extern "C" {
#endif

typedef AG_ARRAY_OF(const char *) VpnRoutes;

struct VpnOsTunnelSettings {
    /** IPv4 address for interface */
    const char *ipv4_address;
    /** IPv6 address for the interface. Specify NULL if you don't need IPv6 */
    const char *ipv6_address;
    /** Included routes **/
    VpnRoutes included_routes;
    /** Excluded routes **/
    VpnRoutes excluded_routes;
    /** MTU of the interface */
    int mtu;
};

struct VpnWinTunnelSettings {
    /** Adapter name */
    const char *adapter_name;
    /** DNS servers addresses */
    AG_ARRAY_OF(const char *) dns_servers;
    /** Library module to handle tunnel */
    HMODULE wintun_lib;
};

VpnOsTunnelSettings *vpn_os_tunnel_settings_clone(const VpnOsTunnelSettings *settings);
void vpn_os_tunnel_settings_destroy(VpnOsTunnelSettings *settings);

VpnWinTunnelSettings *vpn_win_tunnel_settings_clone(const VpnWinTunnelSettings *settings);
void vpn_win_tunnel_settings_destroy(VpnWinTunnelSettings *settings);

/* Exported functions for Win32 CAPI */
/**
 * Default settings for all tunnels
 */
WIN_EXPORT const VpnOsTunnelSettings *vpn_os_tunnel_settings_defaults();
/**
 * Additional default settings for Win tunnel. For common settings, see `vpn_os_tunnel_settings_defaults()`.
 */
WIN_EXPORT const VpnWinTunnelSettings *vpn_win_tunnel_settings_defaults();

#ifdef _WIN32
/**
 * Create Wintun tunnel
 * @param settings Tunnel settings (common). See `vpn_os_tunnel_settings_defaults()` for recommended defaults.
 * @param win_settings Win tunnel settings. See `vpn_win_tunnel_settings_defaults()` for recommended defaults.
 * @return Newly created tunnel or NULL
 */
WIN_EXPORT void *vpn_win_tunnel_create(VpnOsTunnelSettings *settings, VpnWinTunnelSettings *win_settings);
/**
 * Destroy Wintun tunnel
 */
WIN_EXPORT void vpn_win_tunnel_destroy(void *win_tunnel);
/**
 * This function must be used in ping_handler and vpn_handler when tunnel is on.
 * Does nothing if `vpn_win_set_bound_if()` was not previously called, or it was
 * called with 0.
 */
WIN_EXPORT bool vpn_win_socket_protect(evutil_socket_t fd, const sockaddr *addr);
/**
 * Return the network interface which is currently active.
 * May return 0 in case it is not found.
 */
WIN_EXPORT uint32_t vpn_win_detect_active_if();
/**
 * Sets outbound interface that will be used inside `vpn_win_socket_protect()`.
 * The interface may be found with `vpn_win_detect_active_if()`.
 * @param if_index if >0, the library sets it as is
 *                 if =0, the library turns off the socket protection
 *                 (i.e. `vpn_win_socket_protect()` will not actually do anything)
 */
WIN_EXPORT void vpn_win_set_bound_if(uint32_t if_index);

#endif

#ifdef __cplusplus
} // extern "C"

class VpnOsTunnel {
public:
    /** Initialize tunnel */
    virtual VpnError init(const VpnOsTunnelSettings *settings) {
        return {-1, "Init of base tunnel class used"};
    };
    /** Initialize tunnel with windows adapter settings */
    virtual VpnError init_win(const VpnOsTunnelSettings *settings, const VpnWinTunnelSettings *win_settings) {
        return {-1, "Init of base tunnel class used"};
    };
    /** Stop and deinit tunnel */
    virtual void deinit(){};
    /** Get file descriptor */
    virtual evutil_socket_t get_fd() {
        return -1;
    };
    /** Start receiving packets */
    virtual void start_recv_packets(void (*read_callback)(void *arg, VpnPackets *packets),
                                    void *read_callback_arg){};
    /** Stop receiving packets */
    virtual void stop_recv_packets(){};
    /** Send packet */
    virtual void send_packet(std::span<const evbuffer_iovec> chunks){};
    virtual ~VpnOsTunnel() = default;

protected:
    void init_settings(const VpnOsTunnelSettings *settings) {
        m_settings.reset(vpn_os_tunnel_settings_clone(settings));
    }
    DeclPtr<VpnOsTunnelSettings, &vpn_os_tunnel_settings_destroy> m_settings;
    // Interface index
    uint32_t m_if_index;
};

#ifdef __linux__
class VpnLinuxTunnel : public VpnOsTunnel {
public:
    /** Initialize tunnel */
    VpnError init(const VpnOsTunnelSettings *settings) override;
    /** Get file descriptor */
    evutil_socket_t get_fd() override;
    /** Stop and deinit tunnel */
    void deinit() override;
    ~VpnLinuxTunnel() override = default;

private:
    evutil_socket_t tun_open();
    void setup_if();
    void setup_routes();

    evutil_socket_t m_tun_fd{-1};
    std::string m_tun_name{};
};
#elif __APPLE__ && !TARGET_OS_IPHONE
class VpnMacTunnel : public VpnOsTunnel {
public:
    /** Initialize tunnel */
    VpnError init(const VpnOsTunnelSettings *settings) override;
    /** Get file descriptor */
    evutil_socket_t get_fd() override;
    /** Stop and deinit tunnel */
    void deinit() override;
    ~VpnMacTunnel() override = default;

protected:
    evutil_socket_t tun_open(uint32_t num);
    void setup_if();
    void setup_routes();

private:
    evutil_socket_t m_tun_fd{-1};
    std::string m_tun_name{};
};
#elif _WIN32

class VpnWinTunnel : public VpnOsTunnel {
public:
    /** Initialize tunnel */
    VpnError init_win(const VpnOsTunnelSettings *settings, const VpnWinTunnelSettings *win_settings) override;
    /** Start receiving packets */
    void start_recv_packets(void (*read_callback)(void *arg, VpnPackets *packets), void *read_callback_arg) override;
    /** Stop receiving packets */
    void stop_recv_packets() override;
    /** Send packet */
    void send_packet(std::span<const evbuffer_iovec> chunks) override;
    /** Stop and deinit tunnel */
    void deinit() override;
    ~VpnWinTunnel() override;

private:
    void init_win_settings(const VpnWinTunnelSettings *win_settings) {
        m_win_settings.reset(vpn_win_tunnel_settings_clone(win_settings));
    }
    bool setup_mtu();
    bool setup_dns();
    bool setup_routes();
    DeclPtr<VpnWinTunnelSettings, &vpn_win_tunnel_settings_destroy> m_win_settings;

    WINTUN_ADAPTER_HANDLE m_wintun_adapter{nullptr};
    WINTUN_SESSION_HANDLE m_wintun_session{nullptr};
    std::unique_ptr<std::thread> m_recv_thread_handle{};
};
#endif

/** Return tunnel object for current OS */
std::unique_ptr<ag::VpnOsTunnel> make_vpn_tunnel();

namespace tunnel_utils {
/** execute command in shell and return output as string */
std::string exec_with_output(const char *cmd);
/**
 * Needed because using `__func__` (which is used in `tracelog()`) inside variadic
 * template function causes a compiler error inside fmtlib's headers
 */
void sys_cmd(const std::string &cmd);
template <typename... Ts>
void fsystem(std::string_view fmt, Ts &&...args) {
    sys_cmd(fmt::vformat(fmt, fmt::make_format_args(args...)));
}
void get_setup_routes(std::vector<ag::CidrRange> &ipv4_routes, std::vector<ag::CidrRange> &ipv6_routes,
        ag::VpnRoutes &included_routes, ag::VpnRoutes &excluded_routes);
void split_default_route(std::vector<ag::CidrRange> &routes, ag::CidrRange route);
ag::CidrRange get_address_for_index(const char *ipv4_address, uint32_t index);
} // namespace tunnel_utils

} // namespace ag
#endif
