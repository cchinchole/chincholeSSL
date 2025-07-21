#pragma once
#include <openssl/ec.h>
#include <cstdint>
#include "../inc/types.hpp"
#include "../inc/utils/bytes.hpp"

/* using a byte array[4] to act as a word to make shifting data easier */
#define nB 4             /* Standard for FIPS 197 */
#define AES_BlockSize 16 /* in bytes */
#define AES_MaxWSize 240

class AesContext
{
public:
    cssl::AES_MODE mode_;
    cssl::AES_KEYSIZE key_size_;
    uint8_t state_[nB][nB];
    uint8_t w_[AES_MaxWSize];
    uint8_t iv_[AES_BlockSize];

    AesContext()
    {
        memset(iv_, 0, AES_BlockSize);
        memset(w_, 0, 240);
        memset(state_, 0, nB*nB);
    }
    AesContext(cssl::AES_MODE mode, cssl::AES_KEYSIZE keySize)
    {
        mode_ = mode;
        key_size_ = keySize;
        memset(iv_, 0, AES_BlockSize);
        memset(w_, 0, 240);
        memset(state_, 0, nB*nB);
    }
};

int aes_key_expansion(AesContext &ctx, ByteSpan key);
int aes_set_iv(AesContext &ctx, ByteSpan iv);
ByteArray aes_encrypt(AesContext &ctx, ByteSpan buf);
ByteArray aes_decrypt(AesContext &ctx, ByteSpan buf);
