#ifndef TEST_HPP
#define TEST_HPP
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>
#include "../utils/bytes.hpp"
#include "../hash/sha.hpp"

void testFunction();
void readParameters();
int testPrimesBetweenFuncs();
int testHMAC(char *msg, size_t msg_len, char *key, size_t key_len, char *KAT, int mode, bool quiet = true);
int testSHA_Shake(ByteArray msg, ByteArray KAT, DIGEST_MODE mode, size_t digestSize, bool quiet = true);
int testSHA(char *msg, size_t msg_len, char *KAT, DIGEST_MODE mode, bool quiet = true);
#endif
