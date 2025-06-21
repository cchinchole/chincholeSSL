#include "../inc/crypto/rsa.hpp"
#include <openssl/bn.h>

int main() {

  BIGNUM *myE = BN_new();
  BN_set_word(myE, 0x100000001);
  cRSAKey *cKey = new cRSAKey(4096, myE, true);

  /* This is the roundtrip function from rsa.h */
  unsigned int out_len = 0;
  char *str = "Hello World!";
  unsigned char *cipher = cKey->encrypt(&out_len, str);
  std::string out = (cKey->decrypt(cipher, out_len));
  int strresult = strcmp((char *)str, (char *)out.c_str());
  std::cout << "- - - - - - - - Encryption Decryption self test - - - - - - - -"
            << std::endl
            << "The inputted string: " << str << std::endl
            << "The outputted string: " << out << std::endl
            << "STRCMP returned " << strresult << std::endl
            << "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
            << std::endl;
  return 0;
}
