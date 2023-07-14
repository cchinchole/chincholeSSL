/*
 * OSSL Random Method
 *  1. DRBG Seed
 *  2. DRBG Bytes
 *  3. DRBG Add
 *  4. DRBG Bytes
 *  5. DRBG Status
*/

#include "inc/rand.hpp"
#include "assert.h"

#define DRNG_NO_SUPPORT 0x0 /* For clarity */
#define DRNG_HAS_RDRAND 0x1
#define DRNG_HAS_RDSEED 0x2



// Seed the RNG.  srand() takes an unsigned int, so we just use the first
// sizeof(unsigned int) bytes in the buffer to seed the RNG.
static int stdlib_rand_seed(const void *buf, int num)
{
        assert(num >= sizeof(unsigned int));
        srand( *((unsigned int *) buf) );
        return 0;
}

// Fill the buffer with random bytes.  For each byte in the buffer, we generate
// a random number and clamp it to the range of a byte, 0-255.
static int stdlib_rand_bytes(unsigned char *buf, int num)
{
        for( int index = 0; index < num; ++index )
        {
                buf[index] = rand() % 256;
        }
        return 1;
}

RAND_METHOD stdlib_rand_meth = {
        stdlib_rand_seed,
        stdlib_rand_bytes,
        stdlib_rand_cleanup,
        stdlib_rand_add,
        stdlib_rand_bytes,
        stdlib_rand_status
};


// This is a public-scope accessor method for our table.
RAND_METHOD *RAND_stdlib() { return &stdlib_rand_meth; }