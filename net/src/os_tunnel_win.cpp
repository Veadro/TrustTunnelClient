#include "net/os_tunnel.h"

#include "common/utils.h"
#include <WS2tcpip.h>
#include <cstdarg>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <tchar.h>
#include <winreg.h>
#include <winsock2.h>
#include <winternl.h>
#include <ws2ipdef.h>

// Need to link with Iphlpapi.lib and Ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static const ag::Logger logger("OS_TUNNEL_WIN");

static HANDLE wintun_quit_event;

static std::atomic<uint32_t> g_win_bound_if = 0;

struct WintunThreadParams {
    WINTUN_SESSION_HANDLE session_ptr;
    void (*read_callback)(void *arg, ag::VpnPackets *packets);
    void *read_callback_arg;
};

void ag::tunnel_utils::sys_cmd(const std::string &cmd) {
    char buffer[UNLEN + 1] = {0};
    DWORD buffer_len = UNLEN + 1;
    if (::GetUserNameA(buffer, &buffer_len)) {
        dbglog(logger, "{}: {}", buffer, cmd);
    } else {
        dbglog(logger, "{}", cmd);
    }
    auto output = exec_with_output(cmd.c_str());
    dbglog(logger, "{}", output);
}

static bool initialize_wintun(HMODULE wintun) {
    if (!wintun) {
        return false;
    }
#define X(name) ((*(FARPROC *) &name = GetProcAddress(wintun, #name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID)
            || X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession)
            || X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket)
            || X(WintunReleaseReceivePacket) || X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD last_error = GetLastError();
        FreeLibrary(wintun);
        SetLastError(last_error);
        return false;
    }
    return true;
}

static WINTUN_ADAPTER_HANDLE create_wintun_adapter(std::string_view adapter_name) {
    wintun_quit_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    WINTUN_ADAPTER_HANDLE adapter = WintunCreateAdapter(ag::utils::to_wstring(adapter_name).data(), L"wintun", nullptr);
    if (!adapter) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return nullptr;
    }
    return adapter;
}

static void WINAPI send_wintun_packet(WINTUN_SESSION_HANDLE session, std::span<const evbuffer_iovec> chunks) {
    size_t sum_chunks_len = 0;
    for (int i = 0; i < chunks.size();) {
        sum_chunks_len += chunks[i++].iov_len;
    }
    BYTE *packet = WintunAllocateSendPacket(session, sum_chunks_len);
    if (packet) {
        BYTE *pos = packet;
        for (int i = 0; i < chunks.size(); pos += chunks[i++].iov_len) {
            std::memcpy(pos, chunks[i].iov_base, chunks[i].iov_len);
        }
        WintunSendPacket(session, packet);
    } else {
        warnlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
    }
}

static DWORD WINAPI receive_wintun_packets(std::unique_ptr<WintunThreadParams> params) {
    WINTUN_SESSION_HANDLE session = params->session_ptr;
    HANDLE wait_handles[] = {WintunGetReadWaitEvent(session), wintun_quit_event};
    std::vector<ag::VpnPacket> packets;
    while (true) {
        DWORD packet_size = 0;
        BYTE *packet = WintunReceivePacket(session, &packet_size);
        if (packet) {
            packets.push_back(ag::VpnPacket{.data = packet,
                    .size = packet_size,
                    .destructor =
                            [](void *arg, uint8_t *data) {
                                WintunReleaseReceivePacket((WINTUN_SESSION_HANDLE) arg, data);
                            },
                    .destructor_arg = session});
        } else {
            DWORD last_error = GetLastError();
            // Process accumulated packets before error processing
            ag::VpnPackets read_packets{packets.data(), packets.size()};
            params->read_callback(params->read_callback_arg, &read_packets);
            packets.clear();

            if (last_error == ERROR_NO_MORE_ITEMS) {
                if (WaitForMultipleObjects(std::size(wait_handles), wait_handles, false, INFINITE) == WAIT_OBJECT_0) {
                    continue;
                }
                return ERROR_SUCCESS;
            }
            return last_error;
        }
    }
}

static uint32_t get_wintun_adapter_index(WINTUN_ADAPTER_HANDLE Adapter) {
    NET_LUID_LH interface_luid;
    WintunGetAdapterLUID(Adapter, &interface_luid);
    NET_IFINDEX if_idx = 0;
    ConvertInterfaceLuidToIndex(&interface_luid, &if_idx);
    return if_idx;
}

static WINTUN_SESSION_HANDLE create_wintun_session(
        std::string_view ipv4Address, std::string_view ipv6Address, WINTUN_ADAPTER_HANDLE adapter) {
    MIB_UNICASTIPADDRESS_ROW address_v4_row;
    InitializeUnicastIpAddressEntry(&address_v4_row);
    WintunGetAdapterLUID(adapter, &address_v4_row.InterfaceLuid);
    address_v4_row.Address.Ipv4.sin_family = AF_INET;
    struct sockaddr_in sa {};
    // store this IP address in sa:
    inet_pton(AF_INET, ipv4Address.data(), &(sa.sin_addr));
    address_v4_row.Address.Ipv4.sin_addr = sa.sin_addr;
    address_v4_row.DadState = IpDadStatePreferred;
    auto last_error = CreateUnicastIpAddressEntry(&address_v4_row);
    if (last_error != ERROR_SUCCESS && last_error != ERROR_OBJECT_ALREADY_EXISTS) {
        SetLastError(last_error);
        errlog(logger, "Set ipv4: {}", ag::sys::strerror(ag::sys::last_error()));
        return nullptr;
    }
    if (ipv6Address.data() != nullptr) {
        MIB_UNICASTIPADDRESS_ROW address_v6_row;
        InitializeUnicastIpAddressEntry(&address_v6_row);
        WintunGetAdapterLUID(adapter, &address_v6_row.InterfaceLuid);
        address_v6_row.Address.Ipv6.sin6_family = AF_INET6;
        struct sockaddr_in6 sa6 {};
        // store this IP address in sa:
        inet_pton(AF_INET6, ipv6Address.data(), &(sa6.sin6_addr));
        address_v6_row.Address.Ipv6.sin6_addr = sa6.sin6_addr;
        address_v6_row.DadState = IpDadStatePreferred;
        last_error = CreateUnicastIpAddressEntry(&address_v6_row);
        if (last_error != ERROR_SUCCESS && last_error != ERROR_OBJECT_ALREADY_EXISTS) {
            SetLastError(last_error);
            errlog(logger, "Set ipv6: {}", ag::sys::strerror(ag::sys::last_error()));
            return nullptr;
        }
    }
    WINTUN_SESSION_HANDLE session = WintunStartSession(adapter, WINTUN_MAX_RING_CAPACITY);
    if (!session) {
        errlog(logger, "Init session: {}", ag::sys::strerror(ag::sys::last_error()));
        return nullptr;
    }
    return session;
}

static void set_wintun_close_event() {
    SetEvent(wintun_quit_event);
}

static void close_wintun(WINTUN_SESSION_HANDLE session, WINTUN_ADAPTER_HANDLE adapter) {
    if (session) {
        WintunEndSession(session);
    }
    if (adapter) {
        WintunCloseAdapter(adapter);
    }
}

ag::VpnError ag::VpnWinTunnel::init_win(
        const ag::VpnOsTunnelSettings *settings, const ag::VpnWinTunnelSettings *win_settings) {
    init_settings(settings);
    init_win_settings(win_settings);
    bool wintun_init_success = initialize_wintun(win_settings->wintun_lib);
    if (!wintun_init_success) {
        return {-1, "Unable to init wintun library"};
    }
    m_wintun_adapter = create_wintun_adapter(win_settings->adapter_name);
    if (m_wintun_adapter == nullptr) {
        return {-1, "Unable to create wintun adapter"};
    }
    m_if_index = get_wintun_adapter_index(m_wintun_adapter);
    std::string ipv4_address = tunnel_utils::get_address_for_index(settings->ipv4_address, m_if_index).to_string();
    std::string ipv6_address = tunnel_utils::get_address_for_index(settings->ipv6_address, m_if_index).to_string();
    m_wintun_session = create_wintun_session(ipv4_address, ipv6_address, m_wintun_adapter);
    if (m_wintun_session == nullptr) {
        return {-1, "Unable to create wintun session"};
    }
    if (!setup_mtu()) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return {-1, "Unable to set mtu for wintun session"};
    }
    if (!setup_dns()) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return {-1, "Unable to set dns for wintun session"};
    }
    if (!setup_routes()) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return {-1, "Unable to setup routes for wintun session"};
    }
    return {0, "Tunnel init success"};
}

bool ag::VpnWinTunnel::setup_mtu() {
    MIB_IPINTERFACE_ROW row{};
    row.InterfaceIndex = m_if_index;
    // set mtu for ipv4 and ipv6
    row.Family = AF_INET;
    DWORD error = GetIpInterfaceEntry(&row);
    // needed on ipv4 for correct work
    row.SitePrefixLength = 0;
    row.NlMtu = m_settings->mtu;
    error |= SetIpInterfaceEntry(&row);
    row.Family = AF_INET6;
    error |= GetIpInterfaceEntry(&row);
    row.NlMtu = m_settings->mtu;
    error |= SetIpInterfaceEntry(&row);
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
    return true;
}

bool ag::VpnWinTunnel::setup_dns() {
    DNS_INTERFACE_SETTINGS dns_setting{};
    dns_setting.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    NET_LUID_LH interface_luid;
    WintunGetAdapterLUID(m_wintun_adapter, &interface_luid);
    GUID interface_guid;
    DWORD error = ConvertInterfaceLuidToGuid(&interface_luid, &interface_guid);
    error |= GetInterfaceDnsSettings(interface_guid, &dns_setting);
    std::wstring dns_nameserver_list = ag::utils::to_wstring(ag::utils::join(m_win_settings->dns_servers.data,
            m_win_settings->dns_servers.data + m_win_settings->dns_servers.size, ","));
    dns_setting.Flags = DNS_SETTING_NAMESERVER;
    dns_setting.NameServer = dns_nameserver_list.data();
    error |= SetInterfaceDnsSettings(interface_guid, &dns_setting);
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
    return true;
}

static bool add_adapter_route(const ag::CidrRange &route, uint32_t tun_number, bool ipv6) {
    MIB_IPFORWARD_ROW2 row{};
    InitializeIpForwardEntry(&row);

    IP_ADDRESS_PREFIX prefix;
    if (ipv6) {
        prefix.Prefix.si_family = AF_INET6;
        auto addr = route.get_address_as_string();
        inet_pton(AF_INET6, addr.c_str(), &(prefix.Prefix.Ipv6.sin6_addr));
    } else {
        prefix.Prefix.si_family = AF_INET;
        auto addr = route.get_address_as_string();
        inet_pton(AF_INET, addr.c_str(), &(prefix.Prefix.Ipv4.sin_addr));
    }
    prefix.PrefixLength = route.get_prefix_len();
    row.DestinationPrefix = prefix;
    row.InterfaceIndex = tun_number;

    DWORD error = CreateIpForwardEntry2(&row);

    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
    return true;
}

bool ag::VpnWinTunnel::setup_routes() {
    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    ag::tunnel_utils::get_setup_routes(
            ipv4_routes, ipv6_routes, m_settings->included_routes, m_settings->excluded_routes);

    for (auto &route : ipv4_routes) {
        if (!add_adapter_route(route, m_if_index, false)) {
            return false;
        }
    }

    for (auto &route : ipv6_routes) {
        if (!add_adapter_route(route, m_if_index, true)) {
            return false;
        }
    }
    return true;
}

void ag::VpnWinTunnel::deinit() {
    stop_recv_packets(); // for case when it wasn't called manually
    close_wintun(m_wintun_session, m_wintun_adapter);
    m_wintun_session = nullptr;
    m_wintun_adapter = nullptr;
}

void ag::VpnWinTunnel::start_recv_packets(
        void (*read_callback)(void *arg, VpnPackets *packets), void *read_callback_arg) {
    std::unique_ptr<WintunThreadParams> pass_params(
            new WintunThreadParams{m_wintun_session, read_callback, read_callback_arg});
    m_recv_thread_handle = std::make_unique<std::thread>(receive_wintun_packets, std::move(pass_params));
}

void ag::VpnWinTunnel::send_packet(std::span<const evbuffer_iovec> chunks) {
    send_wintun_packet(m_wintun_session, chunks);
}

void ag::VpnWinTunnel::stop_recv_packets() {
    if (m_recv_thread_handle) {
        dbglog(logger, "Stopping receiving packets");
        set_wintun_close_event();
        m_recv_thread_handle->join();
        m_recv_thread_handle.reset();
        dbglog(logger, "Stopped receiving packets");
    }
}
ag::VpnWinTunnel::~VpnWinTunnel() {
    close_wintun(m_wintun_session, m_wintun_adapter);
}

void *ag::vpn_win_tunnel_create(ag::VpnOsTunnelSettings *settings, ag::VpnWinTunnelSettings *win_settings) {
    auto *tunnel = new ag::VpnWinTunnel{};
    auto res = tunnel->init_win(settings, win_settings);
    if (res.code != 0) {
        dbglog(logger, "Error initializing tunnel: {}", res.text ? res.text : "(null)");
        delete tunnel;
        return nullptr;
    }
    return tunnel;
}

void ag::vpn_win_tunnel_destroy(void *win_tunnel) {
    delete (VpnWinTunnel *) win_tunnel;
}

uint32_t ag::vpn_win_detect_active_if() {
    // first find physical network cards interfaces
    HKEY current_key;
    TCHAR subkey[BUFSIZ];
    TCHAR base_key[] = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards");
    std::vector<GUID> net_ifs;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, base_key, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &current_key)
            == ERROR_SUCCESS) {
        DWORD dw_index = 0;
        while (TRUE) {
            DWORD dw_name_length = BUFSIZ;
            if (RegEnumKeyEx(current_key, dw_index++, subkey, &dw_name_length, nullptr, nullptr, nullptr, nullptr)
                    == ERROR_NO_MORE_ITEMS) {
                break;
            }
            GUID guid{};
            DWORD data_size = 0;
            RegGetValueA(current_key, subkey, TEXT("ServiceName"), RRF_RT_REG_SZ, nullptr, nullptr, &data_size);
            std::string buffer;
            buffer.reserve(data_size);
            DWORD res = RegGetValueA(
                    current_key, subkey, TEXT("ServiceName"), RRF_RT_REG_SZ, nullptr, buffer.data(), &data_size);
            if (res == ERROR_SUCCESS) {
                CLSIDFromString(ag::utils::to_wstring(buffer.c_str()).c_str(), &guid);
                net_ifs.push_back(guid);
            }
        }
        RegCloseKey(current_key);
    }
    // Then choose operational one
    DWORD result_idx = 0;
    for (auto &guid : net_ifs) {
        NET_LUID luid{};
        ConvertInterfaceGuidToLuid(&guid, &luid);
        MIB_IF_ROW2 row{};
        row.InterfaceLuid = luid;
        DWORD error = GetIfEntry2(&row);
        if ((error == ERROR_SUCCESS) && (row.OperStatus == IfOperStatusUp)) {
            result_idx = row.InterfaceIndex;
            break;
        }
    }
    return uint32_t(result_idx);
}

bool ag::vpn_win_socket_protect(evutil_socket_t fd, const sockaddr *addr) {
    uint32_t bound_if = g_win_bound_if;
    if (bound_if == 0) {
        return true;
    }

    SOCKADDR_INET source_best{};
    MIB_IPFORWARD_ROW2 row{};
    SOCKADDR_INET dest{};
    dest.si_family = addr->sa_family;

    if (addr->sa_family == AF_INET) {
        sockaddr_in to_bind{
                .sin_family = addr->sa_family,
        };
        const auto *sin = (const sockaddr_in *) addr;
        dest.Ipv4.sin_addr = sin->sin_addr;
        dest.Ipv4.sin_port = sin->sin_port;
        if (int error = GetBestRoute2(nullptr, bound_if, nullptr, &dest, 0, &row, &source_best);
                error != ERROR_SUCCESS) {
            errlog(logger, "GetBestRoute2(): {}", ag::sys::strerror(error));
            to_bind.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        } else {
            to_bind.sin_addr = source_best.Ipv4.sin_addr;
        }
        // Without `bind()` it may not work or work unexpectedly.
        // https://lists.zx2c4.com/pipermail/wireguard/2019-September/004541.html
        if (0 != bind(fd, (SOCKADDR *) &to_bind, sizeof(to_bind))) {
            errlog(logger, "bind(): {}", ag::sys::strerror(WSAGetLastError()));
            return false;
        }
        if (0 != setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (char *) &bound_if, sizeof(bound_if))) {
            errlog(logger, "setsockopt(): {}", ag::sys::strerror(WSAGetLastError()));
            return false;
        }
    } else if (addr->sa_family == AF_INET6) {
        sockaddr_in6 to_bind{
                .sin6_family = addr->sa_family,
        };
        const auto *sin = (const sockaddr_in6 *) addr;
        dest.Ipv6.sin6_addr = sin->sin6_addr;
        dest.Ipv6.sin6_port = sin->sin6_port;
        if (int error = GetBestRoute2(nullptr, bound_if, nullptr, &dest, 0, &row, &source_best);
                error != ERROR_SUCCESS) {
            errlog(logger, "GetBestRoute2(): {}", ag::sys::strerror(error));
            memcpy(&to_bind.sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback));
        } else {
            to_bind.sin6_addr = source_best.Ipv6.sin6_addr;
            to_bind.sin6_scope_id = source_best.Ipv6.sin6_scope_id;
        }
        // Without `bind()` it may not work or work unexpectedly.
        // https://lists.zx2c4.com/pipermail/wireguard/2019-September/004541.html
        if (0 != bind(fd, (SOCKADDR *) &to_bind, sizeof(to_bind))) {
            errlog(logger, "bind(): {}", ag::sys::strerror(WSAGetLastError()));
            return false;
        }
        if (0 != setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (char *) &bound_if, sizeof(bound_if))) {
            errlog(logger, "setsockopt(): {}", ag::sys::strerror(WSAGetLastError()));
            return false;
        }
    } else {
        errlog(logger, "Unexpected address family: {}", addr->sa_family);
        return false;
    }
    return true;
}

void ag::vpn_win_set_bound_if(uint32_t if_index) {
    g_win_bound_if = if_index;
}
