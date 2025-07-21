#include "../inc/math/primes.hpp"
#include "../internal/primes.hpp"

namespace cssl
{
bool check_if_prime(BIGNUM *w)
{
    return checkPrime(w);
}
void gen_primes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits)
{
    FIPS186_4_GEN_PRIMES(p, q, e, bits, false, NULL);
}
}
