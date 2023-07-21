#include "inc/hash/sha.hpp"
#include "inc/hash/hmac.hpp"
#include "inc/logger.hpp"
#include <math.h>


/* FIPS 198-1 */
int hmac_sha_512(unsigned char *hmac_out, unsigned char *msg, size_t msg_len, unsigned char *key, size_t key_len, SHA_MODE mode)
{
    int B = getSHABlockLengthByMode(mode);
    int L = getSHAReturnLengthByMode(mode);

    SHA2_Context *ctx = new SHA2_Context;
    SHA2_Context *ctx2 = new SHA2_Context;
    SHA2_Context *ctx3 = new SHA2_Context;

    if(mode == SHA_384){
        initSHA384(ctx);
        initSHA384(ctx2);
        initSHA384(ctx3);
    }

    uint8_t *outerKey = (uint8_t*)malloc( B + L );
    uint8_t *innerKey = (uint8_t*)malloc( B + msg_len );
    unsigned char *tmp = (unsigned char*)malloc(getSHAReturnLengthByMode(mode));

    memset(outerKey, 0, B + L);
    memset(innerKey, 0, B + msg_len);

    if(key_len > B)
    {
        sha2_update(key, key_len, ctx);
        sha2_digest(tmp, ctx);
        if(B < L)
        {
            memcpy(outerKey, tmp, B);
            memcpy(innerKey, tmp, B);
        }
        else
        {
            memcpy(outerKey, tmp, L);
            memcpy(innerKey, tmp, L);
        }
    }
    else
    {
        memcpy(outerKey, key, key_len);
        memcpy(innerKey, key, key_len);
    }

    for(int i = 0; i < B; i++)
    {
        outerKey[i] ^= 0x5c;
        innerKey[i] ^= 0x36;
    }

    memcpy(innerKey + B, msg, msg_len);

    sha2_update(innerKey, B + msg_len, ctx2);
    sha2_digest(tmp, ctx2);

    memcpy(outerKey + B, tmp, L);

    sha2_update(outerKey, B + L, ctx3);
    sha2_digest(hmac_out, ctx3);
    return 0;
}

/* FIPS 198-1 */
int hmac_sha1(unsigned char *hmac_out, unsigned char *msg, size_t msg_len, unsigned char *key, size_t key_len)
{
    int B = getSHABlockLengthByMode(SHA_1);
    int L = getSHAReturnLengthByMode(SHA_1);

    SHA1_Context *ctx = new SHA1_Context;
    SHA1_Context *ctx2 = new SHA1_Context;
    SHA1_Context *ctx3 = new SHA1_Context;
    uint8_t *outerKey = (uint8_t*)malloc( B + L );
    uint8_t *innerKey = (uint8_t*)malloc( B + msg_len );
    unsigned char *tmp = (unsigned char*)malloc(getSHAReturnLengthByMode(SHA_1));

    memset(outerKey, 0, B + L);
    memset(innerKey, 0, B + msg_len);

    if(key_len > B)
    {
        sha1_update(key, key_len, ctx);
        sha1_digest(tmp, ctx);
        if(B < L)
        {
            memcpy(outerKey, tmp, B);
            memcpy(innerKey, tmp, B);
        }
        else
        {
            memcpy(outerKey, tmp, L);
            memcpy(innerKey, tmp, L);
        }
    }
    else
    {
        memcpy(outerKey, key, key_len);
        memcpy(innerKey, key, key_len);
    }

    for(int i = 0; i < B; i++)
    {
        outerKey[i] ^= 0x5c;
        innerKey[i] ^= 0x36;
    }

    memcpy(innerKey + B, msg, msg_len);

    sha1_update(innerKey, B + msg_len, ctx2);
    sha1_digest(tmp, ctx2);

    memcpy(outerKey + B, tmp, L);

    sha1_update(outerKey, B + L, ctx3);
    sha1_digest(hmac_out, ctx3);
    return 0;
}



int hmac_sha(SHA_MODE mode, unsigned char *hmac_out, unsigned char *msg, size_t msg_len, unsigned char *key, size_t key_len)
{
    switch(mode)
    {
        case SHA_512:
            hmac_sha_512(hmac_out, msg, msg_len, key, key_len, mode);
            break;
        case SHA_384:
            hmac_sha_512(hmac_out, msg, msg_len, key, key_len, mode);
            break;
        case SHA_1:
            hmac_sha1(hmac_out, msg, msg_len, key, key_len);
            break;
        default:
            hmac_sha_512(hmac_out, msg, msg_len, key, key_len, SHA_512);
            break;
    }
    return 0;
}
