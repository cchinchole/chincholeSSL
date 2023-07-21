#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <chrono>
#include <vector>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <openssl/rand.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "inc/logger.hpp"
#include "inc/defs.hpp"
#include "inc/rsa.hpp"
#include "inc/primes.hpp"
#include "inc/rand.hpp"
#include "inc/hash/sha.hpp"
#include "inc/test.hpp"
#include "inc/hash/hmac.hpp"

const int kBits = 2048;
int keylen;
char *pem_key;

unsigned char *scanHex(char *str, int bytes) {
    unsigned char *ret = (unsigned char*)malloc(bytes);
    memset(ret, 0, bytes);

    for (int i = 0, i2 = 0; i < bytes; i++, i2 += 2) {
        // get value
        for (int j = 0; j < 2; j++) {
            ret[i] <<= 4;
            unsigned char c = str[i2 + j];
            if (c >= '0' && c <= '9') {
                ret[i] += c - '0';
            }
            else if (c >= 'a' && c <= 'f') {
                ret[i] += c - 'a' + 10;
            }
            else if (c >= 'A' && c <= 'F') {
                ret[i] += c - 'A' + 10;
            }
            else {
                free(ret);
                return NULL;
            }
        }
    }

    return ret;
}


int main(int argc, char *argv[]) {
  BIGNUM* myE = BN_new();
  BN_set_word(myE, 0x100000001);

  /* Set the OPENSSL Rng to use our own method. */
  /* This is deprecated needs updated */
  RAND_set_rand_method(RAND_stdlib());

  /* Make a syscall to /dev/urandom for 4 bytes that can be used to seed the prng */
  unsigned char buff[4];
  syscall(SYS_getrandom, buff, 4, GRND_NONBLOCK);

  RAND_seed(&buff, sizeof(buff));

  cRSA *myRsa = new cRSA(kBits, myE, true);


  BIGNUM *bnLongRand = BN_secure_new();
  BN_rand_ex(bnLongRand, 1024, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, BN_CTX_secure_new());
  unsigned char* testBytes = (unsigned char*)malloc(32*sizeof(char));
  RAND_bytes(testBytes, 32);
  roundTrip(myRsa, (char*)"Test string HeRe! HelLO WoRLd!@#$^&*()_+ 1   2 34    567  89\nTest!");
  printf("\n\nTesting long string now.\n\n");
  roundTrip(myRsa, (char*)BN_bn2dec(bnLongRand));


  testSHA_1("abc", "A9993E364706816ABA3E25717850C26C9CD0D89D");


  testSHA_1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");
  testSHA_2("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909");
  unsigned char tmp[getSHAReturnLengthByMode(SHA_1)];
  unsigned char *key = scanHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 20);
  unsigned char *msg = scanHex("4869205468657265", 8);

  SHA2_Context ctx2;
  initSHA384(&ctx2);
  unsigned char hexdigest[getSHAReturnLengthByMode(ctx2.mode)];
  sha2_update( (uint8_t*)"abc", strlen("abc"), &ctx2);
  sha2_digest(hexdigest, &ctx2);

  hmac_sha(SHA_512, tmp, (unsigned char*)"test", 4, (unsigned char*)"test", 4);
  unsigned char *output = byteArrToHexArr(tmp, getSHAReturnLengthByMode(SHA_512)); 
  printf("HMAC: %s\n", output);


  return 0;
}