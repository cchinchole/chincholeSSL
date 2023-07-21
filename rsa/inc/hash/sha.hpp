#include <openssl/bn.h>
#define SHA1_BLOCK_SIZE_BYTES 64
#define SHA2_384512_BLOCK_SIZE_BYTES 128


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

enum SHA_MODE {
    SHA_1,
    SHA_384,
    SHA_512,
    SHA_256,
};

typedef struct SHA2_Context {
    uint64_t bMsg_len[2] = {0, 0};
    SHA_MODE mode = SHA_512;
    uint64_t H[8] = {
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179
    };

    /* Using a pointer system to allow for additional data to be inputted and processed without having to setup a new context. */
    uint statePtr = 0;
    uint8_t state[SHA2_384512_BLOCK_SIZE_BYTES];
} SHA2_Context;



int sha1_update(uint8_t *msg, uint8_t byMsg_len, SHA1_Context *ctx);
int sha1_digest(unsigned char *digest_out, SHA1_Context *ctx);

int sha2_update(uint8_t *msg, uint8_t byMsg_len, SHA2_Context *ctx);
int sha2_digest(unsigned char *digest_out, SHA2_Context *ctx);

int getSHABlockLengthByMode(SHA_MODE mode);
int getSHAReturnLengthByMode(SHA_MODE mode);
int initSHA384(SHA2_Context *ctx);