#pragma once
#include <openssl/ec.h>
#include <cstdint>
#include "../inc/types.hpp"
#include "../inc/utils/bytes.hpp"

/* using a byte array[4] to act as a word to make shifting data easier */
constexpr uint8_t kNb = 4;             /* Standard for FIPS 197 */
constexpr uint8_t kAesBlockSize = 16; /* in bytes */
constexpr uint8_t kAesMaxWSize = 240;

class AesContext
{
public:
    cssl::AES_MODE mode_;
    cssl::AES_KEYSIZE key_size_;
    uint8_t state_[kNb][kNb];
    uint8_t w_[kAesMaxWSize];
    uint8_t iv_[kAesBlockSize];

    AesContext()
    {
        memset(iv_, 0, kAesBlockSize);
        memset(w_, 0, 240);
        memset(state_, 0, kNb*kNb);
    }
    AesContext(cssl::AES_MODE mode, cssl::AES_KEYSIZE keySize)
    {
        mode_ = mode;
        key_size_ = keySize;
        memset(iv_, 0, kAesBlockSize);
        memset(w_, 0, 240);
        memset(state_, 0, kNb*kNb);
    }
};

int aes_key_expansion(AesContext &ctx, ByteSpan key);
int aes_set_iv(AesContext &ctx, ByteSpan iv);
ByteArray aes_encrypt(AesContext &ctx, ByteSpan buf);
ByteArray aes_decrypt(AesContext &ctx, ByteSpan buf);
