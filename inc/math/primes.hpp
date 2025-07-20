#pragma once
#include <openssl/bn.h>

namespace CSSL
{
bool checkIfPrime(BIGNUM *w);
void genPrimes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits);
}
