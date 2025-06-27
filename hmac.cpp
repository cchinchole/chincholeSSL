#include "inc/hash/sha.hpp"
#include "inc/hash/hmac.hpp"
#include "inc/utils/logger.hpp"
#include <math.h>

/* FIPS 198-1 */
int hmac_sha(SHA_Context *ctx, uint8_t *hmac_out, uint8_t *msg, size_t msg_len, uint8_t *key, size_t key_len)
{

    if(ctx->mode != SHA_MODE::SHA_1 && ctx->mode != SHA_MODE::SHA_224 && ctx->mode != SHA_MODE::SHA_256 && ctx->mode != SHA_MODE::SHA_384 && ctx->mode != SHA_MODE::SHA_512)
        return -1;

    int blockLen = getSHABlockLengthByMode(ctx->mode);
    int retLen = getSHAReturnLengthByMode(ctx->mode);

    /* Init and clear the keys */
    uint8_t *outerKey = (uint8_t *)malloc(blockLen + retLen);
    uint8_t *innerKey = (uint8_t *)malloc(blockLen + msg_len);
    uint8_t *tmp = (uint8_t *)malloc(getSHAReturnLengthByMode(ctx->mode));

    memset(outerKey, 0, blockLen + retLen);
    memset(innerKey, 0, blockLen + msg_len);

    /* If our key takes more than one block then we need to digest this into it's own message */
    if (key_len > blockLen)
    {
        sha_update(key, key_len, ctx);
        sha_digest(tmp, ctx);
        /* Find the minimum length for the key to be copied with */
        if (blockLen < retLen)
        {
            memcpy(outerKey, tmp, blockLen);
            memcpy(innerKey, tmp, blockLen);
        }
        else
        {
            memcpy(outerKey, tmp, retLen);
            memcpy(innerKey, tmp, retLen);
        }
    }
    else
    {
        /* The key can fit within a message */
        memcpy(outerKey, key, key_len);
        memcpy(innerKey, key, key_len);
    }

    for (int i = 0; i < blockLen; i++)
    {
        outerKey[i] ^= 0x5c;
        innerKey[i] ^= 0x36;
    }
    /* Digest the inner with message */
    ctx->clear();
    memcpy(innerKey + blockLen, msg, msg_len);
    sha_update(innerKey, blockLen + msg_len, ctx);
    sha_digest(tmp, ctx);

    /* Digest the outer now with the previous result */
    ctx->clear();
    memcpy(outerKey + blockLen, tmp, retLen);
    sha_update(outerKey, blockLen + retLen, ctx);
    sha_digest(hmac_out, ctx);

    free(outerKey);
    free(innerKey);
    free(tmp);
    return 0;
}
