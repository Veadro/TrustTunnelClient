#pragma once

#include <stdint.h>
#ifndef _WIN32
#include <sys/time.h>
#endif

#include <khash.h>
#include <lwip/ip_addr.h>

#include "tcpip/tcpip.h"

namespace ag {

typedef struct {
    ip_addr_t src_ip;  /**< Source IP address of connection */
    uint16_t src_port; /**< Source port of connection */
    ip_addr_t dst_ip;  /**< Original destination IP address of connection */
    uint16_t dst_port; /**< Original destination port of connection */
} AddressPair;

/**
 * Common part of TCP/IP connections
 */
typedef struct {
    uint64_t id;                 /**< Connection request ID */
    AddressPair addr;            /**< Source-destination address pair */
    TcpipCtx *parent_ctx;        /**< Parent tcpip context structure */
    struct timeval conn_timeout; /**< The moment when connection will be timed out */

#if ENABLE_STATISTICS
    uint64_t received_from_server;      /**< Number of bytes received from server */
    uint64_t last_received_from_server; /**< Number of bytes received from server at last notification */
    uint64_t sent_to_server;            /**< Number of bytes sent to server */
    uint64_t last_sent_to_server;       /**< Number of bytes sent to server at last notification */
    struct timeval next_stat_update;    /**< Timestamp of next update of statistics */
#endif

} TcpipConnection;

uint64_t addr_pair_hash(const AddressPair *addr);
bool addr_pair_equals(const AddressPair *lh, const AddressPair *rh);

KHASH_MAP_INIT_INT64(connections_by_id, TcpipConnection *);
KHASH_INIT(connections_by_addr, AddressPair *, TcpipConnection *, 1, addr_pair_hash, addr_pair_equals);

typedef struct {
    khash_t(connections_by_id) * by_id;
    khash_t(connections_by_addr) * by_addr;
} ConnectionTables;

} // namespace ag
