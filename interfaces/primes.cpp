#include "../inc/math/primes.hpp"
#include "../internal/primes.hpp"

namespace cSSL
{
bool checkIfPrime(BIGNUM *w)
{
    return checkPrime(w);
}
int genPrimes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits)
{
    return FIPS186_4_GEN_PRIMES(p, q, e, bits, false, NULL);
}
}
