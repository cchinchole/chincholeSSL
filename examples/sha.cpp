#include "../inc/hash/sha.hpp"
#include "../inc/hash/hmac.hpp"
#include "../inc/utils/bytes.hpp"
#include <cstring>

int main() {
  SHA_MODE mode = SHA_MODE::SHA_512;
  SHA_Context *ctx = SHA_Context_new(mode);
  unsigned char rawDigest[getSHAReturnLengthByMode(mode)];
  uint8_t *msg = (uint8_t *)"Hello World!";
  size_t msg_len = strlen((char *)msg);
  /* These two functions are needed to set the message then digest it into a
   * hash for any suitable sha mode */
  sha_update(msg, msg_len, ctx);
  sha_digest(rawDigest, ctx);
  printf("SHA512: %s\n", byteArrToHexArr(rawDigest, getSHAReturnLengthByMode(mode)));

  /* For usage with hmac */
  hmac_sha(ctx, rawDigest, msg, msg_len, (uint8_t *)"hellokey", 8);
  printf("HMAC SHA512 (KEY) 'hellokey': %s\n", byteArrToHexArr(rawDigest, getSHAReturnLengthByMode(mode)));
  return 0;
}
