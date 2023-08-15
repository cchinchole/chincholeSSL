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

class SHATestCase
{
public:
  size_t data_len;
  bool failed = true; /* Assume failed until set */
  uint8_t *msg_bytes;
  uint8_t *KAT_hash;
  uint8_t *TEST_hash;

  SHATestCase(size_t msg_len, int digest, uint8_t *msg, uint8_t *KAT, uint8_t *Test);
  void setCaseState(bool state);
};

void testFunction();
void readParameters();
int testPrimesBetweenFuncs();
int testHMAC(char *msg, size_t msg_len, char *key, size_t key_len, char *KAT, int mode);
int testSHA_Shake(char *msg, size_t msg_len, char *KAT, int mode, size_t digestSize, bool quiet = false);
int testSHA(char *msg, size_t msg_len, char *KAT, int mode, bool quiet = false);