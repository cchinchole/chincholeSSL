#include "../inc/hash/hash.hpp"
#include "../inc/utils/logger.hpp"

int main()
{
    //Example for oneshot hashing. For SHAKE use Hasher::xof
    ByteArray msg = hex_to_bytes(ascii_to_hex("Hello World!"));
    PRINT("SHA1: {}", cssl::Hasher::hash(msg, cssl::DIGEST_MODE::SHA_1));

    //Example for HMAC
    ByteArray key = hex_to_bytes(ascii_to_hex("HelloKey!"));
    ByteArray hmacDigest = cssl::Hasher::hmac(msg, key, cssl::DIGEST_MODE::SHA_3_512);
    PRINT("HMAC: {}", hmacDigest);

    //Example using update + SHAKE
    cssl::Hasher h(cssl::DIGEST_MODE::SHA_3_SHAKE_128);
    h.update(msg);
    PRINT("Shake 72 bytes: {}", h.xof(72));

    return 0;
}
