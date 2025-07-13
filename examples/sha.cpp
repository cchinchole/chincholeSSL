#include "../inc/hash/sha.hpp"
#include "../inc/hash/hmac.hpp"
#include "../inc/utils/bytes.hpp"
#include <cstring>

int main()
{
    DIGEST_MODE mode = DIGEST_MODE::SHA_3_512;
    SHA_Context *ctx = SHA_Context_new(mode);
    unsigned char rawDigest[getSHAReturnLengthByMode(mode)];
    uint8_t *msg = (uint8_t *)"Hello World!";
    size_t msg_len = strlen((char *)msg);
    /* These two functions are needed to set the message then digest it into a
     * hash for any suitable sha mode */
    SHA_Update(msg, msg_len, ctx);
    SHA_Digest(rawDigest, ctx);
    printf("SHA512: %s\n",
           bytesToHex(
               bytePtrToVector(rawDigest, getSHAReturnLengthByMode(ctx->mode)))
               .c_str());

    ctx->clear();
    /* For usage with hmac */
    delete ctx;

    ctx = SHA_Context_new(DIGEST_MODE::SHA_3_224);
    if (!(hmac_sha(ctx, rawDigest, hexToBytes("2e").data(), 1, hexToBytes("8648ee936c6ebc5ae4bb48c1139a54e3ac5d897beec492dc4d740752").data(), 224 / 8) == 0))
        printf("Failure to HMAC!\n");
    else
        printf("HMAC SHA512 (KEY) 'hellokey': %s\n",
               bytesToHex(bytePtrToVector(rawDigest,
                                          getSHAReturnLengthByMode(ctx->mode)))
                   .c_str());
    delete ctx;
    return 0;
}
