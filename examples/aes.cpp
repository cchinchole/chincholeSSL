#include "../inc/crypto/aes.hpp"
#include "../inc/utils/bytes.hpp"
#include "../inc/utils/logger.hpp"
#include <memory.h>
#include <openssl/crypto.h>

int main() {
    int retCode = 0;
    AES_CTX ctx(AES_MODE::CBC, AES_KEYSIZE::m128);
    std::string aes_kat_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv_key = "000102030405060708090a0b0c0d0e0f";
    std::string cbc_kat = "3243f6a8885a308d313198a2e0370734";
    std::string ctr_iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    AES_KeyExpansion(ctx, hexToBytes(aes_kat_key).data());

    //Not needed for ECB
    AES_SetIV(ctx, hexToBytes(aes_iv_key).data());

    std::vector<uint8_t> buffer = hexToBytes(cbc_kat);
    std::vector<uint8_t> outputA;
    std::vector<uint8_t> outputB;

    outputA.resize(buffer.size());
    outputB.resize(buffer.size());

    AES_Encrypt(ctx, outputA.data(), buffer.data(), buffer.size());
    AES_Decrypt(ctx, outputB.data(), outputA.data(), outputA.size());
    if (!memcmp(buffer.data(), outputB.data(), outputA.size()))
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

    
    /* Now an example of CTR */
    ctx = AES_CTX(AES_MODE::CTR, AES_KEYSIZE::m128);
    AES_SetIV(ctx, hexToBytes(ctr_iv).data());
    AES_Encrypt(ctx, outputA.data(), buffer.data(), buffer.size());
    AES_Decrypt(ctx, outputB.data(), outputA.data(), buffer.size()); //Can also use encrypt, doesn't matter for CTR, but for simplicity will leave it like this.
    if (!memcmp(buffer.data(), outputB.data(), outputB.size()))
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
    OPENSSL_cleanup();
    return retCode;
}
