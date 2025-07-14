#include "../inc/hash/hash.hpp"
#include "../inc/utils/bytes.hpp"
#include "../inc/utils/logger.hpp"

int main()
{
    //Example for oneshot hashing. For SHAKE use Hasher::xof
    ByteArray msg = hexToBytes(asciiToHex("Hello World!"));
    PRINT("SHA1: {}", Hasher::hash(msg, DIGEST_MODE::SHA_1));

    //Example for HMAC
    ByteArray key = hexToBytes(asciiToHex("HelloKey!"));
    ByteArray hmacDigest = Hasher::hmac(msg, key, DIGEST_MODE::SHA_3_512);
    PRINT("HMAC: {}", hmacDigest);

    //Example using update + SHAKE
    Hasher h(DIGEST_MODE::SHA_3_SHAKE_128);
    h.update(msg);
    PRINT("Shake 72 bytes: {}", h.xof(72));
    return 0;
}
