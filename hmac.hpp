#ifndef HMAC_HPP
#define HMAC_HPP
#include <span>
#include "sha.hpp"
#include "inc/utils/bytes.hpp"
//int hmac_sha(SHA_Context *ctx, uint8_t *hmac_out, const uint8_t *msg, size_t msg_len, const uint8_t *key, size_t key_len);
int hmac_sha(DIGEST_MODE digestMode,
             uint8_t *hmac_out,
             std::span<const uint8_t> msg,
             std::span<const uint8_t> key);
#endif
