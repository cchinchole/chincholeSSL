#pragma once
#include "../inc/types.hpp"
#include "../inc/utils/bytes.hpp"
void hmacFinalize(cssl::DIGEST_MODE digestMode, uint8_t* hmac_out,
             ByteSpan msg, ByteSpan key);
