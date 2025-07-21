#include "internal/hmac.hpp"
#include "inc/hash/hash.hpp"
#include <algorithm>
#include <math.h>

using namespace cssl;

/* FIPS 198-1 */
void hmacFinalize(DIGEST_MODE digestMode, uint8_t *hmac_out,
              ByteSpan msg, ByteSpan key)
{
    Hasher h(digestMode);

    size_t blockLen = h.block_length();
    size_t retLen = h.return_length();

    size_t outerKeySize = blockLen + retLen;
    size_t innerKeySize = blockLen + msg.size();

    /* Init and clear the keys */
    auto outerKey = std::make_unique<uint8_t[]>(outerKeySize);
    auto innerKey = std::make_unique<uint8_t[]>(innerKeySize);

    /* If our key takes more than one block then we need to digest this into
     * it's own message */
    if (key.size() > blockLen)
    {
        h.update(key);
        ByteArray tmp = h.digest();

        /* Find the minimum length for the key to be copied with */
        if (blockLen < retLen)
        {
            std::copy_n(tmp.data(), blockLen, outerKey.get());
            std::copy_n(tmp.data(), blockLen, innerKey.get());
        }
        else
        {
            std::copy_n(tmp.data(), retLen, outerKey.get());
            std::copy_n(tmp.data(), retLen, innerKey.get());
        }
    }
    else
    {
        /* The key can fit within a message */
        std::copy_n(key.data(), key.size(), outerKey.get());
        std::copy_n(key.data(), key.size(), innerKey.get());
    }

    for (int i = 0; i < blockLen; i++)
    {
        outerKey[i] ^= 0x5c;
        innerKey[i] ^= 0x36;
    }

    /* Digest the inner with message */
    std::copy_n(msg.data(), msg.size(), innerKey.get() + blockLen);
    h.update(innerKey, innerKeySize);
    ByteArray tmp = h.digest();

    /* Digest the outer now with the previous result */
    std::copy_n(tmp.data(), retLen, outerKey.get() + blockLen);
    h.update(outerKey, outerKeySize);

    std::copy_n(h.digest().data(), retLen, hmac_out);
}
