#include "inc/hash/hash.hpp"
#include "hmac.hpp"
#include "inc/utils/logger.hpp"
#include <algorithm>
#include <math.h>

/* FIPS 198-1 */
int hmac_sha(DIGEST_MODE digestMode,
             uint8_t *hmac_out,
             std::span<const uint8_t> msg,
             std::span<const uint8_t> key)
{
    Hasher h(digestMode);

    size_t blockLen = getSHABlockLengthByMode(digestMode);
    size_t retLen = getSHAReturnLengthByMode(digestMode);

    size_t outerKeySize = blockLen + retLen;
    size_t innerKeySize = blockLen + msg.size();

    /* Init and clear the keys */
    ByteArray outerKey;
    outerKey.reserve(blockLen + retLen);
    outerKey.resize(blockLen + retLen);

    ByteArray innerKey(blockLen + msg.size());
    innerKey.reserve(blockLen  + msg.size());
    innerKey.resize(blockLen  + msg.size());


    /* If our key takes more than one block then we need to digest this into
     * it's own message */
    if (key.size() > blockLen)
    {
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
    memcpy(innerKey.data() + blockLen, msg.data(), msg.size());
    h.update(innerKey);
    ByteArray tmp = h.digest();

    /* Digest the outer now with the previous result */
    memcpy(outerKey.data() + blockLen, tmp.data(), retLen);
    h.update(outerKey);

    memcpy(hmac_out, h.digest().data(), retLen);
    return 0;
}
