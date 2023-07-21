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

void testFunction();
void readParameters();
int testPrimesBetweenFuncs();
int testSHA_1(char *msg, char *KAT);
int testSHA_512(char *msg, char *KAT);
int testSHA_384(char *msg, char *KAT);
int testHMAC(char *msg, char *key, char *KAT, int mode);
unsigned char *byteArrToHexArr(unsigned char *bytes, size_t byte_len);