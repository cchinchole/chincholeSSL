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
int testHMAC(char *msg, char *key, char *KAT, int mode);
int testSHA(char *msg, char *KAT, int mode);
unsigned char *byteArrToHexArr(unsigned char *bytes, size_t byte_len);