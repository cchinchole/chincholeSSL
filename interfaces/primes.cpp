#include "../inc/math/primes.hpp"
#include "../internal/primes.hpp"

namespace CSSL
{
bool checkIfPrime(BIGNUM *w)
{
    return checkPrime(w);
}
void genPrimes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits)
{
    FIPS186_4_GEN_PRIMES(p, q, e, bits, false, NULL);
}
}
