#include "../inc/crypto/aes.hpp"
#include "../inc/utils/bytes.hpp"
#include <memory.h>
#include <openssl/crypto.h>

int main() {
    int retCode = 0;
    AES_CTX *ctx = new AES_CTX();
    ctx->mode = AES_MODE::AES_CBC_128;
    std::string aes_kat_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv_key = "000102030405060708090a0b0c0d0e0f";
    std::string cbc_kat =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c"
        "46"
        "a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    std::string ctr_iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    AES_KeyExpansion(ctx, hexToBytes(aes_kat_key).data());

    //Not needed for ECB
    AES_SetIV(ctx, hexToBytes(aes_iv_key).data());

    std::vector<uint8_t> buffer = hexToBytes(cbc_kat);
    std::vector<uint8_t> outputA;
    std::vector<uint8_t> outputB;

    outputA.resize(buffer.size());
    outputB.resize(buffer.size());

    AES_Encrypt(ctx, outputA.data(), hexToBytes(cbc_kat).data(), buffer.size());
    AES_Decrypt(ctx, outputB.data(), outputA.data(), 64);
    if (!memcmp(hexToBytes(cbc_kat).data(), outputB.data(), 64))
    {
        printf("CBC passed!\n");
    }
    else
    {
        printf("CBC failed.\n");
        retCode = -1;
        goto error;
    }

    outputA.clear();
    outputB.clear();

    ctx->mode = AES_MODE::AES_CTR_128;
    AES_SetIV(ctx, hexToBytes(ctr_iv).data());
    AES_Encrypt(ctx, outputA.data(), hexToBytes(cbc_kat).data(), 64);
    AES_Decrypt(ctx, outputB.data(), outputA.data(), 64); //Can also use encrypt, doesn't matter for CTR, but for simplicity will leave it like this.

    if (!memcmp(hexToBytes(cbc_kat).data(), outputB.data(), 64))
    {
        printf("CTR passed!\n");
    }
    else
    {
        printf("CTR failed.\n");
        retCode = -1;
        goto error;
    }

error:
    delete ctx;
    OPENSSL_cleanup();
    return retCode;
}
