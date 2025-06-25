#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

void testFunction();
void readParameters();
int testPrimesBetweenFuncs();
int testHMAC(char *msg, size_t msg_len, char *key, size_t key_len, char *KAT, int mode, bool quiet = true);
int testSHA_Shake(char *msg, size_t msg_len, char *KAT, int mode, size_t digestSize, bool quiet = true);
int testSHA(char *msg, size_t msg_len, char *KAT, int mode, bool quiet = true);
