#include "../inc/cssl.hpp"

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


    ByteArray key2 = hex_to_bytes("204FFFD28CDA4FAFD0681AE750AC2FC3F06A6B7FB03DE8C20E9654A0D8F20BF1D541945C28");
    ByteArray hmacDigest2 = cssl::Hasher::hmac(hex_to_bytes("9E97D9CB5ABE8F28"), key2, cssl::DIGEST_MODE::SHA_3_512);
    PRINT("HMAC: {}", hmacDigest2);

    return 0;
}
