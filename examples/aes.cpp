#include "../inc/crypto/aes.hpp"
#include "../inc/utils/bytes.hpp"
#include "../inc/utils/logger.hpp"
#include <memory.h>
#include <openssl/crypto.h>

int main()
{
    AES_CTX ctx(AES_MODE::CBC, AES_KEYSIZE::m128);
    std::string aes_kat_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv_key = "000102030405060708090a0b0c0d0e0f";
    std::string cbc_kat = "3243f6a8885a308d313198a2e0370734";
    std::string ctr_iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    AES_KeyExpansion(ctx, hexToBytes(aes_kat_key));
    // Not needed for ECB
    AES_SetIV(ctx, hexToBytes(aes_iv_key));

    std::vector<uint8_t> buffer = hexToBytes(cbc_kat);

    ByteArray cipher = AES_Encrypt(ctx, buffer);
    ByteArray decipher = AES_Decrypt(ctx, cipher);
    PRINT("Original buffer: {}", bytesToHex(buffer));
    PRINT("Cipher Text: {}", bytesToHex(cipher));
    PRINT("Decrypted Text: {}", bytesToHex(decipher));


    //Example of reinitializing with new mode utilizing the same key.
    ctx = AES_CTX(AES_MODE::CTR, AES_KEYSIZE::m128);
    AES_SetIV(ctx, hexToBytes(ctr_iv));
    cipher = AES_Encrypt(ctx, buffer);
    //Can also use encrypt, doesn't matter for CTR, but for simplicity will leave it like this.
    decipher = AES_Decrypt(ctx, cipher);
    PRINT("CTR Original buffer: {}", bytesToHex(buffer));
    PRINT("CTR Cipher Text: {}", bytesToHex(cipher));
    PRINT("CTR Decrypted Text: {}", bytesToHex(decipher));
    return 0;
}
