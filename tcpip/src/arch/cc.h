/**
 * Libevent LWIP port compiler macros
 */

#ifndef ARCH_CC_H
#define ARCH_CC_H

#if !defined(__GNUC__) && !defined(__clang__)
#error Unsupported compiler
#endif // !defined(__GNUC__) && !defined(__clang__)

/**
 * Custom logger function for LWIP, uses common logger
 * @param message Format string
 * @param args... Format arguments
 */
void libevent_lwip_log_debug(const char *message, ...);
#undef LWIP_PLATFORM_DIAG
#define LWIP_PLATFORM_DIAG(x)                                                                                          \
    do {                                                                                                               \
        libevent_lwip_log_debug x;                                                                                     \
    } while (0)

// Determine endianess
#undef BIG_ENDIAN
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#undef LITTLE_ENDIAN
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#undef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__

// Use byteswapping operations on compiler/system (for optimization)
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#define SWAP_BYTES_IN_WORD(w) __builtin_bswap16(w)

#if NO_SYS
#define LWIP_NO_UNISTD_H 1
#ifdef _WIN32
#include <basetsd.h>
#define SSIZE_MAX MAXSSIZE_T
#endif
#endif

#endif /* ARCH_CC_H */
