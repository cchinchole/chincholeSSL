#include "inc/hash/sha.hpp"
#include "inc/hash/hmac.hpp"
#include "inc/logger.hpp"
#include <math.h>


/* FIPS 198-1 */
int hmac_sha_512(uint8_t *hmac_out, uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len)
{
    SHA_512_Context *ctx = new SHA_512_Context;

    int B = getSHABlockLengthByMode(ctx->mode);
    int L = getSHAReturnLengthByMode(ctx->mode);

    uint8_t *outerKey = (uint8_t*)malloc( B + L );
    uint8_t *innerKey = (uint8_t*)malloc( B + msg_len );
    uint8_t *tmp = (uint8_t*)malloc(getSHAReturnLengthByMode(ctx->mode));

    memset(outerKey, 0, B + L);
    memset(innerKey, 0, B + msg_len);

    if(key_len > B)
    {
        sha_update(key, key_len, ctx);
        sha_digest(tmp, ctx);
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

    ctx->clear();
    sha_update(innerKey, B + msg_len, ctx);
    sha_digest(tmp, ctx);

    memcpy(outerKey + B, tmp, L);

    ctx->clear();
    sha_update(outerKey, B + L, ctx);
    sha_digest(hmac_out, ctx);
    return 0;
}

int hmac_sha_384(uint8_t *hmac_out, uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len)
{

    SHA_384_Context *ctx = new SHA_384_Context;

    int B = getSHABlockLengthByMode(ctx->mode);
    int L = getSHAReturnLengthByMode(ctx->mode);

    uint8_t *outerKey = (uint8_t*)malloc( B + L );
    uint8_t *innerKey = (uint8_t*)malloc( B + msg_len );
    uint8_t *tmp = (uint8_t*)malloc(getSHAReturnLengthByMode(ctx->mode));

    memset(outerKey, 0, B + L);
    memset(innerKey, 0, B + msg_len);

    if(key_len > B)
    {
        sha_update(key, key_len, ctx);
        sha_digest(tmp, ctx);
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

    ctx->clear();
    sha_update(innerKey, B + msg_len, ctx);
    sha_digest(tmp, ctx);

    memcpy(outerKey + B, tmp, L);

    ctx->clear();
    sha_update(outerKey, B + L, ctx);
    sha_digest(hmac_out, ctx);
    return 0;
}

/* FIPS 198-1 */
int hmac_sha1(uint8_t *hmac_out, uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len)
{
    SHA_1_Context *ctx = new SHA_1_Context;
    int B = getSHABlockLengthByMode(SHA_1);
    int L = getSHAReturnLengthByMode(SHA_1);

    uint8_t *outerKey = (uint8_t*)malloc( B + L );
    uint8_t *innerKey = (uint8_t*)malloc( B + msg_len );
    uint8_t *tmp = (uint8_t*)malloc(getSHAReturnLengthByMode(SHA_1));

    memset(outerKey, 0, B + L);
    memset(innerKey, 0, B + msg_len);

    if(key_len > B)
    {
        sha_update(key, key_len, ctx);
        sha_digest(tmp, ctx);
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
    ctx->clear();
    sha_update(innerKey, B + msg_len, ctx);
    sha_digest(tmp, ctx);

    memcpy(outerKey + B, tmp, L);

    ctx->clear();
    sha_update(outerKey, B + L, ctx);
    sha_digest(hmac_out, ctx);
    return 0;
}



int hmac_sha(SHA_MODE mode, uint8_t *hmac_out, uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len)
{
    switch(mode)
    {
        case SHA_512:
            hmac_sha_512(hmac_out, msg, msg_len, key, key_len);
            break;
        case SHA_384:
            hmac_sha_384(hmac_out, msg, msg_len, key, key_len);
            break;
        case SHA_1:
            hmac_sha1(hmac_out, msg, msg_len, key, key_len);
            break;
        default:
            hmac_sha_512(hmac_out, msg, msg_len, key, key_len);
            break;
    }
    return 0;
}
