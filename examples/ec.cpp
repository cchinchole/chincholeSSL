#include "../inc/crypto/ec.hpp"
#include <openssl/bn.h>

int main() {
   
  /* Assigning to NULL as they will be generated later */
  cECKey *key = NULL;
  cECSignature *sig = NULL;
  cECKey *myKey2 = new cECKey();
  cECSignature *mySig2 = new cECSignature();

  char *msg = "Hello World";

  if (key == NULL) {
    key = new cECKey();
    FIPS_186_4_B_4_2_KeyPairGeneration(key);
  }

  if (sig == NULL) {
    sig = new cECSignature();
    if (FIPS_186_5_6_4_1_GenerateSignature(sig, msg, strlen(msg), key) != 0)
      printf("Failed to generate signature\n");
  }

  FIPS_186_4_B_4_2_KeyPairGeneration(myKey2);

  if (FIPS_186_5_6_4_1_GenerateSignature(mySig2, msg, strlen(msg), myKey2) != 0)
    printf("Failed to generate signature\n");

  /* Return code of 0 indicates signature match succeeded */
  printf("Verifying against correct signature: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(sig, msg, strlen(msg), key->group, key->pub) == 0
             ? "Passed!"
             : "Failed!");
  /* Return code of -1 indicates signature match failed */
  printf("Verifying against wrong signature: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(mySig2, msg, strlen(msg), key->group, key->pub) ==
                 -1
             ? "Passed!"
             : "Failed!");

  /* Return code of -1 indicates signature match failed */
  printf("Verifying against wrong key: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(sig, msg, strlen(msg), myKey2->group,
                                          myKey2->pub) == -1
             ? "Passed!"
             : "Failed!");
  char foobar[] = "sdfsdfsdfsdfsd0xx00x0z98z8882828kzzkzkzku2228828";

  /* Return code of -1 indicates signature match failed */
  printf("Verifying against wrong message: %s\n",
         FIPS_186_5_6_4_2_VerifySignature(sig, foobar, strlen(msg), key->group, key->pub) ==
                 -1
             ? "Passed!"
             : "Failed!");

  return 0;
}
