#include <openssl/bn.h>

#define SHA1_BLOCK_SIZE_BYTES 64
#define SHA1_NUM_WORDS 16
#define SHA1_ROUNDS 80
#define SHA1_MASK 0x0000000f

typedef struct SHA1_Context {
    uint64_t bMsg_len = 0;
    uint32_t H[5] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
    };

    /* Using a pointer system to allow for additional data to be inputted and processed without having to setup a new context. */
    uint statePtr = 0;
    uint8_t state[SHA1_BLOCK_SIZE_BYTES];
} SHA1_Context;


int sha1_update(uint8_t *msg, uint8_t byMsg_len, SHA1_Context *ctx);
int sha1_digest(unsigned char *digest_out, SHA1_Context *ctx);