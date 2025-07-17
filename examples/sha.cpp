#include "../inc/cssl.hpp"

int main()
{
    //Example for oneshot hashing. For SHAKE use Hasher::xof
    ByteArray msg = hexToBytes(asciiToHex("Hello World!"));
    PRINT("SHA1: {}", cSSL::Hasher::hash(msg, DIGEST_MODE::SHA_1));

    //Example for HMAC
    ByteArray key = hexToBytes(asciiToHex("HelloKey!"));
    ByteArray hmacDigest = cSSL::Hasher::hmac(msg, key, DIGEST_MODE::SHA_3_512);
    PRINT("HMAC: {}", hmacDigest);

    //Example using update + SHAKE
    cSSL::Hasher h(DIGEST_MODE::SHA_3_SHAKE_128);
    h.update(msg);
    PRINT("Shake 72 bytes: {}", h.xof(72));
    return 0;
}
