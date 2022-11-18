#include "wfp_firewall.h"

// clang-format off
#include <windows.h>
#include <fwpmu.h>
// clang-format on

#include "common/logger.h"
#include "common/utils.h"
#include "net/dns_utils.h"
#include "vpn/guid_utils.h"

static ag::Logger g_log{"FIREWALL"}; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

template <typename Func>
ag::WfpFirewallError run_transaction(HANDLE engine_handle, Func &&func) {
    if (DWORD error = FwpmTransactionBegin0(engine_handle, 0); error != ERROR_SUCCESS) {
        return make_error(ag::FE_WFP_ERROR, AG_FMT("FwpmTransactionBegin0 failed with code {:#x}", error));
    }
    if (auto error = std::forward<Func>(func)()) {
        FwpmTransactionAbort0(engine_handle);
        return error;
    }
    if (DWORD error = FwpmTransactionCommit0(engine_handle); error != ERROR_SUCCESS) {
        return make_error(ag::FE_WFP_ERROR, AG_FMT("FwpmTransactionCommit0 failed with code {:#x}", error));
    }
    return nullptr;
}

struct ag::WfpFirewall::Impl {
    HANDLE engine_handle = INVALID_HANDLE_VALUE; // NOLINT(performance-no-int-to-ptr)
    GUID provider_key = ag::random_guid();
    GUID sublayer_key = ag::random_guid();
};

ag::WfpFirewall::WfpFirewall()
        : m_impl{std::make_unique<Impl>()} {
    std::wstring name = L"AdGuard VPN dynamic session";

    FWPM_SESSION0 session{
            .displayData =
                    {
                            .name = name.data(),
                    },
            .flags = FWPM_SESSION_FLAG_DYNAMIC,
            .txnWaitTimeoutInMSec = INFINITE,
    };

    if (DWORD error = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &m_impl->engine_handle);
            error != ERROR_SUCCESS) {
        errlog(g_log, "FwpmEngineOpen0 failed with code {:#x}", error);
        return;
    }

    auto register_base_objects = [&]() -> WfpFirewallError {
        std::wstring name = L"AdGuard VPN provider";

        FWPM_PROVIDER0 provider{
                .providerKey = m_impl->provider_key,
                .displayData =
                        {
                                .name = name.data(),
                        },
        };

        if (DWORD error = FwpmProviderAdd0(m_impl->engine_handle, &provider, nullptr); error != ERROR_SUCCESS) {
            return make_error(FE_WFP_ERROR, AG_FMT("FwpmProviderAdd0 failed with code {:#x}", error));
        }

        name = L"AdGuard VPN sublayer";
        FWPM_SUBLAYER0 sublayer{
                .subLayerKey = m_impl->sublayer_key,
                .displayData =
                        {
                                .name = name.data(),
                        },
        };

        if (DWORD error = FwpmSubLayerAdd0(m_impl->engine_handle, &sublayer, nullptr); error != ERROR_SUCCESS) {
            return make_error(FE_WFP_ERROR, AG_FMT("FwpmSubLayerAdd0 failed with code {:#x}", error));
        }
    };

    if (auto error = run_transaction(m_impl->engine_handle, std::move(register_base_objects))) {
        errlog(g_log, "Failed to register base objects: {}", error->str());
        FwpmEngineClose0(m_impl->engine_handle);
        m_impl->engine_handle = INVALID_HANDLE_VALUE;
    }
}

ag::WfpFirewall::~WfpFirewall() {
    if (m_impl->engine_handle != INVALID_HANDLE_VALUE) {
        FwpmEngineClose0(m_impl->engine_handle);
    }
}

ag::WfpFirewallError ag::WfpFirewall::restrict_dns_to(std::basic_string_view<sockaddr *> allowed) {
    if (m_impl->engine_handle == INVALID_HANDLE_VALUE) {
        return make_error(FE_NOT_INITIALIZED);
    }
    return run_transaction(m_impl->engine_handle, [&]() -> WfpFirewallError {
        static constexpr uint8_t DENY_WEIGHT = 14;
        static constexpr uint8_t ALLOW_WEIGHT = 15;

        FWPM_FILTER_CONDITION0 deny_conditions[] = {
                {
                        .fieldKey = FWPM_CONDITION_IP_REMOTE_PORT,
                        .matchType = FWP_MATCH_EQUAL,
                        .conditionValue =
                                {
                                        .type = FWP_UINT16,
                                        .uint16 = ag::dns_utils::PLAIN_DNS_PORT_NUMBER,
                                },
                },
                {
                        .fieldKey = FWPM_CONDITION_IP_PROTOCOL,
                        .matchType = FWP_MATCH_EQUAL,
                        .conditionValue =
                                {
                                        .type = FWP_UINT8,
                                        .uint8 = IPPROTO_TCP,
                                },
                },
                {
                        .fieldKey = FWPM_CONDITION_IP_PROTOCOL,
                        .matchType = FWP_MATCH_EQUAL,
                        .conditionValue =
                                {
                                        .type = FWP_UINT8,
                                        .uint8 = IPPROTO_UDP,
                                },
                },
        };

        std::wstring name = L"AdGuard VPN restrict DNS";
        FWPM_FILTER0 filter{
                .displayData =
                        {
                                .name = name.data(),
                        },
                .providerKey = &m_impl->provider_key,
                .subLayerKey = m_impl->sublayer_key,
                .weight =
                        {
                                .type = FWP_UINT8,
                                .uint8 = DENY_WEIGHT,
                        },
                .numFilterConditions = std::size(deny_conditions),
                .filterCondition = &deny_conditions[0],
                .action =
                        {
                                .type = FWP_ACTION_BLOCK,
                        },
        };

        // Block all inbound/outbound IPv4/IPv6 DNS traffic.
        for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                     FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
            filter.layerKey = layer_key;
            if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                    error != ERROR_SUCCESS) {
                return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
            }
        }

        filter.action = {.type = FWP_ACTION_PERMIT};
        filter.weight.uint8 = ALLOW_WEIGHT;

        // Allow IPv4 inbound/outbound DNS traffic for specified addresses.
        std::vector<FWPM_FILTER_CONDITION0> allow_v4_conditions;
        allow_v4_conditions.reserve(std::size(deny_conditions) + allowed.size());
        allow_v4_conditions.insert(allow_v4_conditions.end(), std::begin(deny_conditions), std::end(deny_conditions));
        for (const sockaddr *address : allowed) {
            if (address->sa_family != AF_INET) {
                continue;
            }
            allow_v4_conditions.emplace_back(FWPM_FILTER_CONDITION0{
                    .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    .matchType = FWP_MATCH_EQUAL,
                    .conditionValue =
                            {
                                    .type = FWP_UINT32,
                            },
            });
            std::memcpy(&allow_v4_conditions.back().conditionValue.uint32, sockaddr_get_ip_ptr(address),
                    sizeof(allow_v4_conditions.back().conditionValue.uint32));
            allow_v4_conditions.back().conditionValue.uint32 = htonl(allow_v4_conditions.back().conditionValue.uint32);
        }
        if (allow_v4_conditions.size() > std::size(deny_conditions)) {
            filter.numFilterConditions = allow_v4_conditions.size();
            filter.filterCondition = allow_v4_conditions.data();
            for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
                filter.layerKey = layer_key;
                if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                        error != ERROR_SUCCESS) {
                    return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                }
            }
        }

        // Allow IPv6 inbound/outbound DNS traffic for specified addresses.
        std::vector<FWPM_FILTER_CONDITION0> allow_v6_conditions;
        allow_v6_conditions.reserve(std::size(deny_conditions) + allowed.size());
        allow_v6_conditions.insert(allow_v6_conditions.end(), std::begin(deny_conditions), std::end(deny_conditions));
        std::vector<FWP_BYTE_ARRAY16> allow_v6_addresses;
        allow_v6_addresses.reserve(allowed.size());
        for (const sockaddr *address : allowed) {
            if (address->sa_family != AF_INET6) {
                continue;
            }
            allow_v6_addresses.emplace_back();
            std::memcpy(&allow_v6_addresses.back().byteArray16[0], sockaddr_get_ip_ptr(address),
                    sizeof(allow_v6_addresses.back().byteArray16));
            allow_v6_conditions.emplace_back(FWPM_FILTER_CONDITION0{
                    .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    .matchType = FWP_MATCH_EQUAL,
                    .conditionValue =
                            {
                                    .type = FWP_BYTE_ARRAY16_TYPE,
                                    .byteArray16 = &allow_v6_addresses.back(),
                            },
            });
        }
        if (allow_v6_conditions.size() > std::size(deny_conditions)) {
            filter.numFilterConditions = allow_v6_conditions.size();
            filter.filterCondition = allow_v6_conditions.data();
            for (GUID layer_key : {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
                filter.layerKey = layer_key;
                if (DWORD error = FwpmFilterAdd0(m_impl->engine_handle, &filter, nullptr, nullptr);
                        error != ERROR_SUCCESS) {
                    return make_error(FE_WFP_ERROR, AG_FMT("FwpmFilterAdd0 failed with code {:#x}", error));
                }
            }
        }

        return nullptr;
    });
}
