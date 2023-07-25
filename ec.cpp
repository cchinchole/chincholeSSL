#include "inc/crypto/ec.hpp"
#include "inc/math/primes.hpp"



/* FIPS 186-4 */
/* 1. Curve over prime field, identified by P-xxx */
/* E: y^2 = x^3-3x+b (mod p) */




/*

SP 800-56 5.6.1.2 ECC Key-Pair Generation

TODO:
    Define a structure to hold the key
    Define a structure to hold a point


    Generate the private key within the range of 0, order
    From the private key define it as a new point within the group
    Then multiply 
*/

int ec_generate_key(  )
{
    BN_CTX *ctx = BN_CTX_new();
    const char P192N[] = "6277101735386680763835789423176059013767194773182842284081";
    cECKey key;
    BN_dec2bn(&key.order, P192N);

    BN_priv_rand_range_ex(key.priv, key.order, 0, ctx);
}