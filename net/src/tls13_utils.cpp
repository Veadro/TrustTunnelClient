#include "net/tls13_utils.h"

#include "common/defs.h"
#include "openssl/evp.h"
#include "openssl/hkdf.h"
#include <span>

namespace ag::tls13_utils {

bool hkdf_extract(std::span<uint8_t> dest, std::span<const uint8_t> secret, std::span<const uint8_t> salt) {
    // SHA256 is used for QUIC [rfc 9001 5.2]
    const EVP_MD *prf = EVP_sha256();
    size_t dest_len = EVP_MD_size(prf);
    if (dest.size() < dest_len) {
        return false;
    }

    return HKDF_extract(dest.data(), &dest_len, prf, secret.data(), secret.size(), salt.data(), salt.size()) == 1;
}

bool hkdf_expand_label(std::span<uint8_t> dest, std::span<const uint8_t> secret, std::string_view label,
        std::span<const uint8_t> context) {

    std::string full_label = std::string("tls13 ") + label.data();
    std::basic_string<uint8_t> info;
    // 2 first bytes store out key length
    info.push_back((uint8_t) (dest.size() >> CHAR_BIT));
    info.push_back((uint8_t) dest.size());
    // 3rd byte stores label length
    info.push_back((uint8_t) full_label.size());
    info.append((uint8_t *) full_label.c_str());
    // Context length
    info.push_back((uint8_t) context.size());
    info.append(context.data(), context.size());

    const EVP_MD *prf = EVP_sha256();
    return HKDF_expand(dest.data(), dest.size(), prf, secret.data(), secret.size(),
                   (uint8_t *) info.data(), info.size()) == 1;
}

}
