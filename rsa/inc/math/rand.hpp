#include <openssl/rand.h>


// These don't need to do anything if you don't have anything for them to do.
static void stdlib_rand_cleanup() {}
static int stdlib_rand_add(const void *buf, int num, double add_entropy) {return 0;}
static int stdlib_rand_status() { return 1; }

static int stdlib_rand_seed(const void *buf, int num);
static int stdlib_rand_bytes(unsigned char *buf, int num);


// Create the table that will link OpenSSL's rand API to our functions.
extern RAND_METHOD stdlib_rand_meth;

extern RAND_METHOD *RAND_stdlib();