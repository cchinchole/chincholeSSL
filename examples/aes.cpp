#include "../inc/crypto/aes.hpp"
#include <memory.h>
#include "../inc/utils/bytes.hpp"

int main() {
  AES_CTX *ctx = new AES_CTX();
  ctx->mode = AES_CBC_128;

    std::string aes_kat_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv_key = "000102030405060708090a0b0c0d0e0f";

    std::string cbc_kat =
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46"
      "a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    std::string ctr_iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

  FIPS_197_5_2_KeyExpansion(ctx, hexToBytes(aes_kat_key).data());
  SetIV(ctx, hexToBytes(aes_iv_key).data());
  uint8_t *outA = (uint8_t *)malloc(64);
  uint8_t *outB = (uint8_t *)malloc(64);

  CBC_Encrypt(ctx, outA, hexToBytes(cbc_kat).data(), 64);
  printf("CBC Encrypt: %s\n", printWord(outA, 64, 16));
  CBC_Decrypt(ctx, outB, outA, 64);
  printf("CBC Decrypt: %s\n", printWord(outB, 64, 16));
  if (!memcmp(hexToBytes(cbc_kat).data(), outB, 64))
    printf("CBC passed!\n");
  else
    printf("CBC failed.\n");

  memset(outA, 0, 64);
  memset(outB, 0, 64);

  SetIV(ctx, hexToBytes(ctr_iv).data());
  CTR_xcrypt(ctx, outA, hexToBytes(cbc_kat).data(), 64);
  printf("CTR Encrypt: %s\n", printWord(outA, 64, 16));

  CTR_xcrypt(ctx, outB, outA, 64);
  printf("CTR Decrypt: %s\n", printWord(outB, 64, 16));
  if (!memcmp(hexToBytes(cbc_kat).data(), outB, 64))
    printf("CTR Decrypt passed!\n");
  else
    printf("CTR Decrypt failed.\n");

  for (int i = 0; i < 64; i++) {
    if (outB[i] != hexToBytes(cbc_kat).data()[i]) {
      printf("Failure found on %d: %02x %02x\n", i, outB[i],
             hexToBytes(cbc_kat).data()[i]);
    }
  }
    
  return 0;
}
