#ifndef HMAC_HPP
#define HMAC_HPP
#include <span>
#include "sha.hpp"
#include "inc/utils/bytes.hpp"
void hmac_sha(DIGEST_MODE digestMode, uint8_t *hmac_out,
             ByteSpan msg, ByteSpan key);
#endif
