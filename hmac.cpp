#include "internal/hmac.hpp"
#include "inc/hash/hash.hpp"
#include <algorithm>
#include <math.h>

using namespace cssl;

/* FIPS 198-1 */
void hmacFinalize(DIGEST_MODE digest_mode, uint8_t *hmac_out,
              ByteSpan msg, ByteSpan key)
{
    Hasher h(digest_mode);

    size_t len_block = h.block_length();
    size_t len_return = h.return_length();

    size_t outer_keysize = len_block + len_return;
    size_t inner_keysize = len_block + msg.size();

    /* Init and clear the keys */
    auto outer_key = std::make_unique<uint8_t[]>(outer_keysize);
    auto inner_key = std::make_unique<uint8_t[]>(inner_keysize);

    /* If our key takes more than one block then we need to digest this into
     * it's own message */
    if (key.size() > len_block)
    {
        h.update(key);
        ByteArray tmp = h.digest();

        /* Find the minimum length for the key to be copied with */
        if (len_block < len_return)
        {
            std::copy_n(tmp.data(), len_block, outer_key.get());
            std::copy_n(tmp.data(), len_block, inner_key.get());
        }
        else
        {
            std::copy_n(tmp.data(), len_return, outer_key.get());
            std::copy_n(tmp.data(), len_return, inner_key.get());
        }
    }
    else
    {
        /* The key can fit within a message */
        std::copy_n(key.data(), key.size(), outer_key.get());
        std::copy_n(key.data(), key.size(), inner_key.get());
    }

    for (int i = 0; i < len_block; i++)
    {
        outer_key[i] ^= 0x5c;
        inner_key[i] ^= 0x36;
    }

    /* Digest the inner with message */
    std::copy_n(msg.data(), msg.size(), inner_key.get() + len_block);
    h.update(inner_key, inner_keysize);
    ByteArray tmp = h.digest();

    /* Digest the outer now with the previous result */
    std::copy_n(tmp.data(), len_return, outer_key.get() + len_block);
    h.update(outer_key, outer_keysize);

    std::copy_n(h.digest().data(), len_return, hmac_out);
}
