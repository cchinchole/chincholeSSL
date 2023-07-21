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
#include "inc/test.hpp"
#include <math.h>
#include "inc/json.hpp"
#include "inc/hash/sha.hpp"
#include "inc/primes.hpp"

unsigned char *byteArrToHexArr(unsigned char *bytes, size_t byte_len)
{

    unsigned char *dest = (unsigned char*) malloc(2*byte_len + 1);
    if (!dest) return NULL;

    unsigned char *p = dest;
    for (size_t i = 0;  i < byte_len;  ++i) {
        p += sprintf((char*)p, "%02hhX", bytes[i]);
    }
    return dest;
}

void readParameters()
{
    std::ifstream f("test.json");
    nlohmann::json data = nlohmann::json::parse(f);
    BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new();

    auto &trials = data["test-data"];
    for(auto &testData : trials)
    {
        std::cout << "name: " << testData["name"].get<std::string>() << std::endl;
        BN_set_word(p, testData["age"].get<std::int64_t>());
        printf("\n%s\n", BN_bn2dec(p));
    }
}

void testFunction()
{
    nlohmann::json j;
    j["pi"] = 3.14159;
    j["happy"] = true;
    j["list"] = {1,2,3};
    std::ofstream o("test.json");
    o << j << std::endl;
}

int testPrimesBetweenFuncs()
{
  
  BIGNUM* testPrime = BN_secure_new();
  int s = 0, j = 0;
  for(int i = 4; i < 17863; i++)
  {
  BN_set_word(testPrime, i);
  if(miller_rabin_is_prime(testPrime, 64))
    if(BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
      s++;
    else
      j++;
  else
    if(BN_check_prime(testPrime, BN_CTX_secure_new(), NULL))
      j++;
  }
  printf("Primes found: %d Discrepancies between other func: %d\n", s, j);
  BN_free(testPrime);
  
  return 0;
}

int testSHA_1(char *msg, char *KAT)
{ 
  unsigned char rawDigest[getSHAReturnLengthByMode(SHA_1)];
  SHA1_Context ctx;
  sha1_update( (uint8_t*)msg, strlen(msg), &ctx);
  sha1_digest(rawDigest, &ctx);
  unsigned char *hexString = byteArrToHexArr(rawDigest, getSHAReturnLengthByMode(SHA_1));


  int res = strcmp((char*)hexString, KAT);
  res==0 ? printf("(SHA1 Test) HASH Returned: %s PASSED!\n", hexString) : printf("HASH Returned: %s FAILED!\n", hexString);
  return res;
}

int testSHA_2(char *msg, char *KAT)
{ 
  unsigned char rawDigest[getSHAReturnLengthByMode(SHA_512)];
  SHA2_Context ctx;
  sha2_update( (uint8_t*)msg, strlen(msg), &ctx);
  sha2_digest(rawDigest, &ctx);
  unsigned char *hexString = byteArrToHexArr(rawDigest, getSHAReturnLengthByMode(SHA_512));


  int res = strcmp((char*)hexString, KAT);
  res==0 ? printf("(SHA2 Test) HASH Returned: %s PASSED!\n", hexString) : printf("HASH Returned: %s FAILED!\n", hexString);
  return res;
}




