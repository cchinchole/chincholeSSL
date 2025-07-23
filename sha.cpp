#include "internal/sha.hpp"

constexpr static uint32_t kSha1H0[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
                        0xc3d2e1f0};

constexpr static uint32_t kSha224H0[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                          0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

constexpr static uint32_t kSha256H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

constexpr static uint64_t kSha384H0[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
    0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

constexpr static uint64_t kSha512H0[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                          0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                          0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                          0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};


Sha3Context::Sha3Context(cssl::DIGEST_MODE mode)
{
    mode_ = mode;
    switch (mode)
    {
    case cssl::DIGEST_MODE::SHA_3_224:
        this->digest_bytes_ = 224 / 8;
        break;
    case cssl::DIGEST_MODE::SHA_3_256:
        this->digest_bytes_ = 256 / 8;
        break;
    case cssl::DIGEST_MODE::SHA_3_384:
        this->digest_bytes_ = 384 / 8;
        break;
    case cssl::DIGEST_MODE::SHA_3_512:
        this->digest_bytes_ = 512 / 8;
        break;
    default:
        this->digest_bytes_ = 0;
        break;
    }
    memset(&sponge_, 0, sizeof(sponge_));
    this->block_cursor_ = 0;
    switch(mode)
    {
        case cssl::DIGEST_MODE::SHA_3_SHAKE_128:
            r_ = 1344/8;
            break;
        case cssl::DIGEST_MODE::SHA_3_SHAKE_256:
            r_ = 1088/8;
            break;
        default:
            r_ = (kSha3Words * 8) - (2 * (digest_bytes_));
            break;
    }
    this->ph_ = nullptr;
    this->pmsg_len_ = nullptr;
    this->pblock_ = nullptr;
}

void sha3_shake_digest_bytes(ShaContext *ctx_raw, size_t digestBytes)
{
    Sha3Context *ctx = (Sha3Context*)ctx_raw;
    ctx->digest_bytes_ = digestBytes;
}

void Sha3Context::clear()
{
    memset(&this->sponge_, 0, sizeof(this->sponge_));
    this->block_cursor_ = 0;
}

Sha1Context::Sha1Context()
{
    /* Set the pointers */
    pmsg_len_ = &msglen_;
    ph_ = &h_;
    pblock_ = &block_;

    mode_ = cssl::DIGEST_MODE::SHA_1;
    msglen_ = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha1BlockSizeBytes);
}
void Sha1Context::clear()
{
    msglen_ = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha1BlockSizeBytes);
    for (int i = 0; i < 5; i++)
    {
        h_[i] = kSha1H0[i];
    }
}

Sha224Context::Sha224Context()
{
    /* Set the pointers */
    pmsg_len_ = &msglen_;
    ph_ = &h_;
    pblock_ = &block_;

    mode_ = cssl::DIGEST_MODE::SHA_224;
    msglen_ = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha256BlockSizeBytes);
}
void Sha224Context::clear()
{
    msglen_ = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha256BlockSizeBytes);
    for (int i = 0; i < 8; i++)
    {
        h_[i] = kSha224H0[i];
    }
}

Sha256Context::Sha256Context()
{
    /* Set the pointers */
    pmsg_len_ = &msglen_;
    ph_ = &h_;
    pblock_ = &block_;

    mode_ = cssl::DIGEST_MODE::SHA_256;
    msglen_ = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha256BlockSizeBytes);
}
void Sha256Context::clear()
{
    msglen_ = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha256BlockSizeBytes);
    for (int i = 0; i < 8; i++)
    {
        h_[i] = kSha256H0[i];
    }
}

Sha512Context::Sha512Context()
{
    /* Set the pointers */
    pmsg_len_ = &msglen_;
    ph_ = &h_;
    pblock_ = &block_;

    mode_ = cssl::DIGEST_MODE::SHA_512;
    msglen_[0] = 0;
    msglen_[1] = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha512BlockSizeBytes);
}
void Sha512Context::clear()
{
    msglen_[0] = 0;
    msglen_[1] = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha512BlockSizeBytes);

    for (int i = 0; i < 8; i++)
    {
        h_[i] = kSha512H0[i];
    }
}

Sha384Context::Sha384Context()
{
    /* Set the pointers */
    pmsg_len_ = &msglen_;
    ph_ = &h_;
    pblock_ = &block_;

    mode_ = cssl::DIGEST_MODE::SHA_384;
    msglen_[0] = 0;
    msglen_[1] = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha512BlockSizeBytes);
}
void Sha384Context::clear()
{
    msglen_[0] = 0;
    msglen_[1] = 0;
    block_cursor_ = 0;
    memset(block_, 0, kSha512BlockSizeBytes);
    for (int i = 0; i < 8; i++)
    {
        h_[i] = kSha384H0[i];
    }
}

int get_block_length(cssl::DIGEST_MODE mode)
{
    switch (mode)
    {
    case cssl::DIGEST_MODE::SHA_1:
        return kSha1BlockSizeBytes;
        break;
    case cssl::DIGEST_MODE::SHA_224:
    case cssl::DIGEST_MODE::SHA_256:
        return kSha256BlockSizeBytes;
        break;
    case cssl::DIGEST_MODE::SHA_384:
    case cssl::DIGEST_MODE::SHA_512:
        return kSha512BlockSizeBytes;
        break;
    case cssl::DIGEST_MODE::SHA_3_224:
        return 1152/8;
        break;
    case cssl::DIGEST_MODE::SHA_3_256:
        return 1088/8;
        break;
    case cssl::DIGEST_MODE::SHA_3_384:
        return 832/8;
        break;
    case cssl::DIGEST_MODE::SHA_3_512:
        return 576/8;
        break;
    case cssl::DIGEST_MODE::SHA_3_SHAKE_128:
        return 1344/8;
        break;
    case cssl::DIGEST_MODE::SHA_3_SHAKE_256:
        return 1088/8;
        break;
    default:
        return 0;
        break;
    }
    return -1;
}
int get_return_length(cssl::DIGEST_MODE mode)
{
    switch (mode)
    {
    case cssl::DIGEST_MODE::SHA_1:
        return 160 / 8;
        break;
    case cssl::DIGEST_MODE::SHA_3_224:
    case cssl::DIGEST_MODE::SHA_224:
        return 224 / 8;
        break;
    case cssl::DIGEST_MODE::SHA_3_256:
    case cssl::DIGEST_MODE::SHA_256:
        return 256 / 8;
        break;
    case cssl::DIGEST_MODE::SHA_3_384:
    case cssl::DIGEST_MODE::SHA_384:
        return 384 / 8;
        break;
    case cssl::DIGEST_MODE::SHA_512:
    case cssl::DIGEST_MODE::SHA_3_512:
        return 512 / 8;
        break;
    default:
        return -1;
        break;
    }
    return -1;
}
char *sha_mode_name(cssl::DIGEST_MODE mode)
{
    switch (mode)
    {
    case cssl::DIGEST_MODE::SHA_1:
        return (char *)"SHA_1";
        break;
    case cssl::DIGEST_MODE::SHA_224:
        return (char *)"SHA_224";
        break;
    case cssl::DIGEST_MODE::SHA_256:
        return (char *)"SHA_256";
        break;
    case cssl::DIGEST_MODE::SHA_384:
        return (char *)"SHA_384";
        break;
    case cssl::DIGEST_MODE::SHA_512:
        return (char *)"SHA_512";
        break;
    case cssl::DIGEST_MODE::SHA_3_224:
        return (char *)"SHA_3_224";
        break;
    case cssl::DIGEST_MODE::SHA_3_256:
        return (char *)"SHA_3_256";
        break;
    case cssl::DIGEST_MODE::SHA_3_384:
        return (char *)"SHA_3_384";
        break;
    case cssl::DIGEST_MODE::SHA_3_512:
        return (char *)"SHA_3_512";
        break;
    default:
        return (char *)"";
        break;
    }
    return (char *)"";
}
int sha_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx)
{
    switch (ctx->mode_)
    {
    case cssl::DIGEST_MODE::SHA_1:
        sha1_update(msg, byMsg_len, (Sha1Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_224:
        sha256_update(msg, byMsg_len, (Sha224Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_256:
        sha256_update(msg, byMsg_len, (Sha256Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_384:
        sha512_update(msg, byMsg_len, (Sha384Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_512:
        sha512_update(msg, byMsg_len, (Sha512Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_3_224:
    case cssl::DIGEST_MODE::SHA_3_256:
    case cssl::DIGEST_MODE::SHA_3_384:
    case cssl::DIGEST_MODE::SHA_3_512:
    case cssl::DIGEST_MODE::SHA_3_SHAKE_128:
    case cssl::DIGEST_MODE::SHA_3_SHAKE_256:
        sha3_update(msg, byMsg_len, ctx);
        break;
    default:
        break;
    }
    return 0;
}
int sha_digest(uint8_t *digest_out, ShaContext *ctx)
{
    switch (ctx->mode_)
    {
    case cssl::DIGEST_MODE::SHA_1:
        sha1_digest(digest_out, (Sha1Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_224:
        sha256_digest(digest_out, (Sha224Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_256:
        sha256_digest(digest_out, (Sha256Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_512:
        sha512_digest(digest_out, (Sha512Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_384:
        sha512_digest(digest_out, (Sha384Context *)ctx);
        break;
    case cssl::DIGEST_MODE::SHA_3_224:
    case cssl::DIGEST_MODE::SHA_3_256:
    case cssl::DIGEST_MODE::SHA_3_384:
    case cssl::DIGEST_MODE::SHA_3_512:
        sha3_digest(digest_out, ctx);
        break;
    case cssl::DIGEST_MODE::SHA_3_SHAKE_128:
    case cssl::DIGEST_MODE::SHA_3_SHAKE_256:
        sha3_shake_digest(digest_out, ((Sha3Context*)ctx)->digest_bytes_, ctx);
        break;
    default:
        break;
    }
    return 0;
}

ShaContext *sha_new_context(cssl::DIGEST_MODE mode)
{
    ShaContext *ctx = NULL;
    switch (mode)
    {
    case cssl::DIGEST_MODE::SHA_1:
        ctx = new Sha1Context();
        break;
    case cssl::DIGEST_MODE::SHA_224:
        ctx = new Sha224Context();
        break;
    case cssl::DIGEST_MODE::SHA_256:
        ctx = new Sha256Context();
        break;
    case cssl::DIGEST_MODE::SHA_384:
        ctx = new Sha384Context();
        break;
    case cssl::DIGEST_MODE::SHA_512:
        ctx = new Sha512Context();
        break;
    case cssl::DIGEST_MODE::SHA_3_224:
    case cssl::DIGEST_MODE::SHA_3_256:
    case cssl::DIGEST_MODE::SHA_3_384:
    case cssl::DIGEST_MODE::SHA_3_512:
    case cssl::DIGEST_MODE::SHA_3_SHAKE_128:
    case cssl::DIGEST_MODE::SHA_3_SHAKE_256:
        ctx = new Sha3Context(mode);
        break;
    default:
        ctx = new Sha1Context();
        break;
    }
    return ctx;
}
