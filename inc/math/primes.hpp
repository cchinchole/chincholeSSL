#pragma once
#include <openssl/bn.h>

namespace cSSL
{
bool checkIfPrime(BIGNUM *w);
int genPrimes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits);
}
