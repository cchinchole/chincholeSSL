#ifndef SHA_HPP
#define SHA_HPP
#include <openssl/bn.h>
#include <stdio.h>
#include <memory.h>

#define SHA1_BLOCK_SIZE_BYTES 64
#define SHA256_BLOCK_SIZE_BYTES 64
#define SHA2_384512_BLOCK_SIZE_BYTES 128
#define SHA3_WORDS 25     /* 1600/8 / sizeof(uint64_t) */
#define SHA3_SPONGE_ARR 5 /* 25 / 5*/

enum SHA_MODE
{
    SHA_1,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_3_224,
    SHA_3_256,
    SHA_3_384,
    SHA_3_512,
    SHA_3_SHAKE_128,
    SHA_3_SHAKE_256,
    NONE
};

class SHA_Context
{
private:
public:
    uint64_t blockCur = 0;
    SHA_MODE mode = SHA_1;
    void *HP;
    void *bMsg_lenP;
    void *blockP;
    virtual void clear() {}
    virtual ~SHA_Context() {}
};

class SHA_3_Context : public SHA_Context
{
private:
public:
    uint8_t digestBytes = 0;
    uint32_t r = 0;

    union
    {
        uint8_t bytes[SHA3_WORDS * 8];
        uint64_t words[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR];
    } sponge;

    SHA_3_Context(SHA_MODE mode);
    void clear();
};

class SHA_1_Context : public SHA_Context
{
private:
    uint64_t bMsg_len = 0;
    uint32_t H[5] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0};
    uint8_t block[SHA1_BLOCK_SIZE_BYTES];

public:
    SHA_1_Context();

    void clear();
};

class SHA_224_Context : public SHA_Context
{
private:
    uint64_t bMsg_len = 0;
    uint32_t H[8] = {
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4};
    uint8_t block[SHA256_BLOCK_SIZE_BYTES];

public:
    SHA_224_Context();

    void clear();
};

class SHA_256_Context : public SHA_Context
{
private:
    uint64_t bMsg_len = 0;
    uint32_t H[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19};
    uint8_t block[SHA256_BLOCK_SIZE_BYTES];

public:
    SHA_256_Context();

    void clear();
};

class SHA_512_Context : public SHA_Context
{
private:
    uint64_t bMsg_len[2] = {0, 0};
    uint8_t block[SHA2_384512_BLOCK_SIZE_BYTES];
    uint64_t H[8] = {
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179};

public:
    SHA_512_Context();
    void clear();
};

class SHA_384_Context : public SHA_Context
{
private:
    uint64_t bMsg_len[2] = {0, 0};
    uint8_t block[SHA2_384512_BLOCK_SIZE_BYTES];
    uint64_t H[8] = {
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4};

public:
    SHA_384_Context();
    void clear();
};

char *SHA_MODE_NAME(SHA_MODE mode);
int getSHABlockLengthByMode(SHA_MODE mode);
int getSHAReturnLengthByMode(SHA_MODE mode);
SHA_Context *SHA_Context_new(SHA_MODE mode);

int SHA_384512_update(uint8_t *msg, size_t byMsg_len, SHA_Context *ctx);
int SHA_384512_digest(uint8_t *digest_out, SHA_Context *ctx);

int SHA_1_update(uint8_t *msg, size_t byMsg_len, SHA_Context *ctx);
int SHA_1_digest(uint8_t *digest_out, SHA_Context *ctx);

int SHA_224256_update(uint8_t *msg, size_t byMsg_len, SHA_Context *ctx);
int SHA_224256_digest(uint8_t *digest_out, SHA_Context *ctx);

int SHA_3_update(uint8_t *msg, size_t byMsg_len, SHA_3_Context *ctx);
int SHA_3_digest(uint8_t *digest_out, SHA_3_Context *ctx);

int SHA_3_xof(SHA_3_Context *ctx);
int SHA_3_shake_digest(uint8_t *digestOut, size_t digestLen, SHA_3_Context *ctx);

int sha_update(uint8_t *msg, size_t byMsg_len, SHA_Context *ctx);
int sha_digest(uint8_t *digest_out, SHA_Context *ctx);
#endif
