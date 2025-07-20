#include <openssl/ec.h>
#include <stdio.h>
#include <memory>
#include <cstdint>
#include "../inc/types.hpp"
#include "../inc/utils/bytes.hpp"

/* using a byte array[4] to act as a word to make shifting data easier */

#define nB 4             /* Standard for FIPS 197 */
#define AES_BlockSize 16 /* in bytes */

/* Can use this to cast the buffer without having to manually set the 16 bytes */
// using state_t = uint8_t[4][4];

class AES_CTX
{
public:
    AES_MODE mode;
    AES_KEYSIZE ksize;
    uint8_t state[nB][nB];
    uint8_t w[240];            // Round Key; setting to maximum size for AES256
    uint8_t iv[AES_BlockSize]; // IV For CBC

    AES_CTX(AES_MODE mode, AES_KEYSIZE ksize)
    {
        this->mode = mode;
        this->ksize = ksize;
        memset(iv, 0, AES_BlockSize);
        memset(w, 0, 240);
        memset(state, 0, nB*nB);
    }
};

int keyExpansion(AES_CTX &ctx, ByteSpan key);
int aSetIV(AES_CTX &ctx, ByteSpan iv);
ByteArray aEncrypt(AES_CTX &ctx, ByteSpan buf);
ByteArray aDecrypt(AES_CTX &ctx, ByteSpan buf);
