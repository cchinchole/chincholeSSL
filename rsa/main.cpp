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

uint8_t *scanHex(char *str, int bytes) {
    uint8_t *ret = (uint8_t*)malloc(bytes);
    memset(ret, 0, bytes);

    for (int i = 0, i2 = 0; i < bytes; i++, i2 += 2) {
        // get value
        for (int j = 0; j < 2; j++) {
            ret[i] <<= 4;
            uint8_t c = str[i2 + j];
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


  testSHA("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983E441C3BD26EBAAE4AA1F95129E5E54670F1", SHA_1);
  testSHA("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039", SHA_384);
  testSHA("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909", SHA_512);
  testHMAC( (char*)scanHex("4869205468657265", 8) , (char*)scanHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 20) , "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", SHA_512);
  testHMAC( (char*)scanHex("4869205468657265", 8) , (char*)scanHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 20) , "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6", SHA_384);
  testHMAC( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "78e2e78c51a4b45a95536c4a1fa2bf72cfbd8f0b", SHA_1);


  return 0;
}