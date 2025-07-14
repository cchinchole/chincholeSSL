#include "inc/hash/hash.hpp"
#include "hmac.hpp"
#include "inc/utils/logger.hpp"
#include <math.h>

/* FIPS 198-1 */
int hmac_sha(DIGEST_MODE digestMode,
             uint8_t *hmac_out,
             const ByteArray msg,
             const ByteArray key)
{

    /*
    if (ctx->mode != DIGEST_MODE::SHA_1 && ctx->mode != DIGEST_MODE::SHA_224 &&
        ctx->mode != DIGEST_MODE::SHA_256 && ctx->mode != DIGEST_MODE::SHA_384 &&
        ctx->mode != DIGEST_MODE::SHA_512)
        return -1;
    */

    Hasher h(digestMode);

    int blockLen = getSHABlockLengthByMode(digestMode);
    int retLen = getSHAReturnLengthByMode(digestMode);

    /* Init and clear the keys */
    //uint8_t *outerKey = (uint8_t *)malloc(blockLen + retLen);
    //uint8_t *innerKey = (uint8_t *)malloc(blockLen + msg.size());
    ByteArray outerKey(blockLen + retLen);
    ByteArray innerKey(blockLen + msg.size());
    //memset(outerKey, 0, blockLen + retLen);
    //memset(innerKey, 0, blockLen + msg.size());

    /* If our key takes more than one block then we need to digest this into
     * it's own message */
    if (key.size() > blockLen)
    {
        //TODO: SHA_Update(key, key_len, ctx);
        //TODO: SHA_Digest(tmp, ctx);
        h.update(key);
        ByteArray tmp = h.digest();
        /* Find the minimum length for the key to be copied with */
        if (blockLen < retLen)
        {
            memcpy(outerKey.data(), tmp.data(), blockLen);
            memcpy(innerKey.data(), tmp.data(), blockLen);
        }
        else
        {
            memcpy(outerKey.data(), tmp.data(), retLen);
            memcpy(innerKey.data(), tmp.data(), retLen);
        }
    }
    else
    {
        /* The key can fit within a message */
        memcpy(outerKey.data(), key.data(), key.size());
        memcpy(innerKey.data(), key.data(), key.size());
    }

    for (int i = 0; i < blockLen; i++)
    {
        outerKey[i] ^= 0x5c;
        innerKey[i] ^= 0x36;
    }
    /* Digest the inner with message */
    //TODO: ctx->clear();
    h.reset();
    memcpy(innerKey.data() + blockLen, msg.data(), msg.size());
    h.update(innerKey);
    ByteArray tmp = h.digest();
    //SHA_Update(innerKey, blockLen + msg.size(), ctx);
    //SHA_Digest(tmp, ctx);

    /* Digest the outer now with the previous result */
    //ctx->clear();
    h.reset();
    memcpy(outerKey.data() + blockLen, tmp.data(), retLen);
    h.update(outerKey);
    memcpy(hmac_out, h.digest().data(), retLen);
    //SHA_Update(outerKey, blockLen + retLen, ctx);
    //SHA_Digest(hmac_out, ctx);

    //free(outerKey);
    //free(innerKey);
    //free(tmp);
    return 0;
}
