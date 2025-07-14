#include <openssl/ec.h>
#include <stdio.h>
#include <memory>
#include <cstdint>
#include "../utils/bytes.hpp"

/* using a byte array[4] to act as a word to make shifting data easier */

#define nB 4             /* Standard for FIPS 197 */
#define AES_BlockSize 16 /* in bytes */

/* Can use this to cast the buffer without having to manually set the 16 bytes */
// using state_t = uint8_t[4][4];

enum class AES_MODE
{
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    NONE
};

enum class AES_KEYSIZE
{
    m128 = 0,
    m192 = 1,
    m256 = 2
};

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

//int getNR(AES_MODE mode);
//int getNK(AES_MODE mode);
//int FIPS_197_5_2_KeyExpansion(AES_CTX *ctx, uint8_t *key);
//int FIPS_197_5_1_Cipher(AES_CTX *ctx); // Using a X to signify this is a two way buffer
//int FIPS_197_5_3_InvCipher(AES_CTX *ctx);
//int CBC_Encrypt(AES_CTX *ctx, uint8_t *output, uint8_t *buf, size_t buf_len);
//int CBC_Decrypt(AES_CTX *ctx, uint8_t *output, uint8_t *buf, size_t buf_len);
//int CTR_xcrypt(AES_CTX *ctx, uint8_t *out, uint8_t *buf, size_t buf_len);
int AES_KeyExpansion(AES_CTX &ctx, ByteSpan key);
int AES_SetIV(AES_CTX &ctx, ByteSpan iv);
ByteArray AES_Encrypt(AES_CTX &ctx, ByteSpan buf);
ByteArray AES_Decrypt(AES_CTX &ctx, ByteSpan buf);
