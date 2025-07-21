#include "../inc/cssl.hpp"
#include "utils/logger.hpp"
#include <memory.h>
#include <openssl/crypto.h>

int main()
{
    std::string aes_kat_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv_key = "000102030405060708090a0b0c0d0e0f";
    std::string cbc_kat = "3243f6a8885a308d313198a2e0370734";
    std::string ctr_iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    cssl::Aes aes(cssl::AES_MODE::CBC, cssl::AES_KEYSIZE::m128);
    
    //In ECB Mode, the IV is not provided. i.e. addKey(key);
    //Can add via a span<uint8_t> or std::string
    aes.load_key(hex_to_bytes(aes_kat_key), hex_to_bytes(aes_iv_key));

    std::vector<uint8_t> buffer = hex_to_bytes(cbc_kat);
    ByteArray cipher = aes.encrypt(buffer);
    ByteArray decipher = aes.decrypt(cipher);
    PRINT("CBC Mode");
    PRINT("Original buffer: {}", bytes_to_hex(buffer));
    PRINT("Cipher Text: {}", bytes_to_hex(cipher));
    PRINT("Decrypted Text: {}\n", bytes_to_hex(decipher));

    //Reinitializing against CTR now
    aes = cssl::Aes(cssl::AES_MODE::CTR, cssl::AES_KEYSIZE::m128);
    aes.load_key(aes_kat_key, ctr_iv);
    
    //Can also use encrypt, doesn't matter for CTR, but for simplicity will leave it like this.
    cipher = aes.encrypt(buffer);
    decipher = aes.decrypt(cipher);

    PRINT("CTR Mode");
    PRINT("CTR Original buffer: {}", bytes_to_hex(buffer));
    PRINT("CTR Cipher Text: {}", bytes_to_hex(cipher));
    PRINT("CTR Decrypted Text: {}", bytes_to_hex(decipher));
    return 0;
}
