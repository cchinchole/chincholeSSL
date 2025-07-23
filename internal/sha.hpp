#pragma once
#include <openssl/bn.h>
#include <stdio.h>
#include <memory.h>
#include "../inc/types.hpp"

constexpr int kSha1BlockSizeBytes = 64;
constexpr int kSha256BlockSizeBytes = 64;
constexpr int kSha512BlockSizeBytes = 128;
constexpr int kSha3Words = 25;     /* 1600/8 / sizeof(uint64_t) */
constexpr int kSha3SpongeArr = 5; /* 25 / 5*/

class ShaContext
{
private:
public:
    uint64_t block_cursor_ = 0;
    cssl::DIGEST_MODE mode_ = cssl::DIGEST_MODE::SHA_1;
    void* ph_;
    void* pmsg_len_;
    void* pblock_;
    virtual void clear() {}
    virtual ~ShaContext() {}
};

class Sha3Context : public ShaContext
{
private:
public:
    size_t digest_bytes_ = 0;
    uint32_t r_ = 0;

    union
    {
        uint8_t bytes[kSha3Words * 8];
        uint64_t words[kSha3SpongeArr][kSha3SpongeArr];
    } sponge_;

    Sha3Context(cssl::DIGEST_MODE mode);
    void clear();
};

class Sha1Context : public ShaContext
{
private:
    uint64_t msglen_ = 0;
    uint32_t h_[5] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0};
    uint8_t block_[kSha1BlockSizeBytes];

public:
    Sha1Context();

    void clear();
};

class Sha224Context : public ShaContext
{
private:
    uint64_t msglen_ = 0;
    uint32_t h_[8] = {
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4};
    uint8_t block_[kSha256BlockSizeBytes];

public:
    Sha224Context();

    void clear();
};

class Sha256Context : public ShaContext
{
private:
    uint64_t msglen_ = 0;
    uint32_t h_[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19};
    uint8_t block_[kSha256BlockSizeBytes];

public:
    Sha256Context();

    void clear();
};

class Sha512Context : public ShaContext
{
private:
    uint64_t msglen_[2] = {0, 0};
    uint8_t block_[kSha512BlockSizeBytes];
    uint64_t h_[8] = {
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179};

public:
    Sha512Context();
    void clear();
};

class Sha384Context : public ShaContext
{
private:
    uint64_t msglen_[2] = {0, 0};
    uint8_t block_[kSha512BlockSizeBytes];
    uint64_t h_[8] = {
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4};

public:
    Sha384Context();
    void clear();
};

ShaContext *sha_new_context(cssl::DIGEST_MODE mode);
int get_block_length(cssl::DIGEST_MODE mode);
int get_return_length(cssl::DIGEST_MODE mode);
char *sha_mode_name(cssl::DIGEST_MODE mode);
void sha3_shake_digest_bytes(ShaContext *ctx_raw, size_t digestBytes);

int sha1_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha256_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha512_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha3_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha1_digest(uint8_t *digest_out, ShaContext *ctx);
int sha256_digest(uint8_t *digest_out, ShaContext *ctx);
int sha512_digest(uint8_t *digest_out, ShaContext *ctx);
int sha3_digest(uint8_t *digest_out, ShaContext *ctx);
int sha3_shake_digest(uint8_t *digestOut, size_t digestLen, ShaContext *ctx);
int sha3_xof(ShaContext *ctx);

int sha_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha_digest(uint8_t *digest_out, ShaContext *ctx);
