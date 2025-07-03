#ifndef HMAC_HPP
#define HMAC_HPP
#include "sha.hpp"
int hmac_sha(SHA_Context *ctx, uint8_t *hmac_out, uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len);
#endif
