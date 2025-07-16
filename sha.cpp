#include "internal/sha.hpp"

uint32_t SHA_1_H0[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
                        0xc3d2e1f0};

uint32_t SHA_224_H0[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                          0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

uint32_t SHA_256_H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

uint64_t SHA_512_H0[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                          0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                          0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                          0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

uint64_t SHA_384_H0[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                          0x9159015a3070dd17, 0x152fecd8f70e5939,
                          0x67332667ffc00b31, 0x8eb44a8768581511,
                          0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

SHA_3_Context::SHA_3_Context(DIGEST_MODE mode)
{
    this->mode = mode;
    switch (mode)
    {
    case DIGEST_MODE::SHA_3_224:
        this->digestBytes = 224 / 8;
        break;
    case DIGEST_MODE::SHA_3_256:
        this->digestBytes = 256 / 8;
        break;
    case DIGEST_MODE::SHA_3_384:
        this->digestBytes = 384 / 8;
        break;
    case DIGEST_MODE::SHA_3_512:
        this->digestBytes = 512 / 8;
        break;
    default:
        this->digestBytes = 0;
        break;
    }
    memset(&sponge, 0, sizeof(sponge));
    this->blockCur = 0;
    switch(mode)
    {
        case DIGEST_MODE::SHA_3_SHAKE_128:
            r = 1344/8;
            break;
        case DIGEST_MODE::SHA_3_SHAKE_256:
            r = 1088/8;
            break;
        default:
            r = (SHA3_WORDS * 8) - (2 * (digestBytes));
            break;
    }
    this->HP = nullptr;
    this->bMsg_lenP = nullptr;
    this->blockP = nullptr;
}

void SHA_SHAKE_DIGEST_BYTES(SHA_Context *ctx_raw, size_t digestBytes)
{
    SHA_3_Context *ctx = (SHA_3_Context*)ctx_raw;
    ctx->digestBytes = digestBytes;
}

void SHA_3_Context::clear()
{
    memset(&this->sponge, 0, sizeof(this->sponge));
    this->blockCur = 0;
}

SHA_1_Context::SHA_1_Context()
{
    /* Set the pointers */
    bMsg_lenP = &bMsg_len;
    HP = &H;
    blockP = &block;

    mode = DIGEST_MODE::SHA_1;
    bMsg_len = 0;
    blockCur = 0;
    memset(block, 0, SHA1_BLOCK_SIZE_BYTES);
}
void SHA_1_Context::clear()
{
    bMsg_len = 0;
    blockCur = 0;
    memset(block, 0, SHA1_BLOCK_SIZE_BYTES);
    for (int i = 0; i < 5; i++)
    {
        H[i] = SHA_1_H0[i];
    }
}

SHA_224_Context::SHA_224_Context()
{
    /* Set the pointers */
    bMsg_lenP = &bMsg_len;
    HP = &H;
    blockP = &block;

    mode = DIGEST_MODE::SHA_224;
    bMsg_len = 0;
    blockCur = 0;
    memset(block, 0, SHA256_BLOCK_SIZE_BYTES);
}
void SHA_224_Context::clear()
{
    bMsg_len = 0;
    blockCur = 0;
    memset(block, 0, SHA256_BLOCK_SIZE_BYTES);
    for (int i = 0; i < 8; i++)
    {
        H[i] = SHA_224_H0[i];
    }
}

SHA_256_Context::SHA_256_Context()
{
    /* Set the pointers */
    bMsg_lenP = &bMsg_len;
    HP = &H;
    blockP = &block;

    mode = DIGEST_MODE::SHA_256;
    bMsg_len = 0;
    blockCur = 0;
    memset(block, 0, SHA256_BLOCK_SIZE_BYTES);
}
void SHA_256_Context::clear()
{
    bMsg_len = 0;
    blockCur = 0;
    memset(block, 0, SHA256_BLOCK_SIZE_BYTES);
    for (int i = 0; i < 8; i++)
    {
        H[i] = SHA_256_H0[i];
    }
}

SHA_512_Context::SHA_512_Context()
{
    /* Set the pointers */
    bMsg_lenP = &bMsg_len;
    HP = &H;
    blockP = &block;

    mode = DIGEST_MODE::SHA_512;
    bMsg_len[0] = 0;
    bMsg_len[1] = 0;
    blockCur = 0;
    memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);
}
void SHA_512_Context::clear()
{
    bMsg_len[0] = 0;
    bMsg_len[1] = 0;
    blockCur = 0;
    memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);

    for (int i = 0; i < 8; i++)
    {
        H[i] = SHA_512_H0[i];
    }
}

SHA_384_Context::SHA_384_Context()
{
    /* Set the pointers */
    bMsg_lenP = &bMsg_len;
    HP = &H;
    blockP = &block;

    mode = DIGEST_MODE::SHA_384;
    bMsg_len[0] = 0;
    bMsg_len[1] = 0;
    blockCur = 0;
    memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);
}
void SHA_384_Context::clear()
{
    bMsg_len[0] = 0;
    bMsg_len[1] = 0;
    blockCur = 0;
    memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);
    for (int i = 0; i < 8; i++)
    {
        H[i] = SHA_384_H0[i];
    }
}

int getSHABlockLengthByMode(DIGEST_MODE mode)
{
    switch (mode)
    {
    case DIGEST_MODE::SHA_1:
        return SHA1_BLOCK_SIZE_BYTES;
        break;
    case DIGEST_MODE::SHA_224:
    case DIGEST_MODE::SHA_256:
        return SHA256_BLOCK_SIZE_BYTES;
        break;
    case DIGEST_MODE::SHA_384:
    case DIGEST_MODE::SHA_512:
        return SHA2_384512_BLOCK_SIZE_BYTES;
        break;
    case DIGEST_MODE::SHA_3_224:
        return 1152/8;
        break;
    case DIGEST_MODE::SHA_3_256:
        return 1088/8;
        break;
    case DIGEST_MODE::SHA_3_384:
        return 832/8;
        break;
    case DIGEST_MODE::SHA_3_512:
        return 576/8;
        break;
    case DIGEST_MODE::SHA_3_SHAKE_128:
        return 1344/8;
        break;
    case DIGEST_MODE::SHA_3_SHAKE_256:
        return 1088/8;
        break;
    default:
        return 0;
        break;
    }
    return -1;
}
int getSHAReturnLengthByMode(DIGEST_MODE mode)
{
    switch (mode)
    {
    case DIGEST_MODE::SHA_1:
        return 160 / 8;
        break;
    case DIGEST_MODE::SHA_3_224:
    case DIGEST_MODE::SHA_224:
        return 224 / 8;
        break;
    case DIGEST_MODE::SHA_3_256:
    case DIGEST_MODE::SHA_256:
        return 256 / 8;
        break;
    case DIGEST_MODE::SHA_3_384:
    case DIGEST_MODE::SHA_384:
        return 384 / 8;
        break;
    case DIGEST_MODE::SHA_512:
    case DIGEST_MODE::SHA_3_512:
        return 512 / 8;
        break;
    default:
        return -1;
        break;
    }
    return -1;
}
char *DIGEST_MODE_NAME(DIGEST_MODE mode)
{
    switch (mode)
    {
    case DIGEST_MODE::SHA_1:
        return (char *)"SHA_1";
        break;
    case DIGEST_MODE::SHA_224:
        return (char *)"SHA_224";
        break;
    case DIGEST_MODE::SHA_256:
        return (char *)"SHA_256";
        break;
    case DIGEST_MODE::SHA_384:
        return (char *)"SHA_384";
        break;
    case DIGEST_MODE::SHA_512:
        return (char *)"SHA_512";
        break;
    case DIGEST_MODE::SHA_3_224:
        return (char *)"SHA_3_224";
        break;
    case DIGEST_MODE::SHA_3_256:
        return (char *)"SHA_3_256";
        break;
    case DIGEST_MODE::SHA_3_384:
        return (char *)"SHA_3_384";
        break;
    case DIGEST_MODE::SHA_3_512:
        return (char *)"SHA_3_512";
        break;
    default:
        return (char *)"";
        break;
    }
    return (char *)"";
}
int SHA_Update(const uint8_t *msg, size_t byMsg_len, SHA_Context *ctx)
{
    switch (ctx->mode)
    {
    case DIGEST_MODE::SHA_1:
        SHA_1_update(msg, byMsg_len, (SHA_1_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_224:
        SHA_224256_update(msg, byMsg_len, (SHA_224_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_256:
        SHA_224256_update(msg, byMsg_len, (SHA_256_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_384:
        SHA_384512_update(msg, byMsg_len, (SHA_384_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_512:
        SHA_384512_update(msg, byMsg_len, (SHA_512_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_3_224:
    case DIGEST_MODE::SHA_3_256:
    case DIGEST_MODE::SHA_3_384:
    case DIGEST_MODE::SHA_3_512:
    case DIGEST_MODE::SHA_3_SHAKE_128:
    case DIGEST_MODE::SHA_3_SHAKE_256:
        SHA_3_update(msg, byMsg_len, ctx);
        break;
    default:
        break;
    }
    return 0;
}
int SHA_Digest(uint8_t *digest_out, SHA_Context *ctx)
{
    switch (ctx->mode)
    {
    case DIGEST_MODE::SHA_1:
        SHA_1_digest(digest_out, (SHA_1_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_224:
        SHA_224256_digest(digest_out, (SHA_224_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_256:
        SHA_224256_digest(digest_out, (SHA_256_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_512:
        SHA_384512_digest(digest_out, (SHA_512_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_384:
        SHA_384512_digest(digest_out, (SHA_384_Context *)ctx);
        break;
    case DIGEST_MODE::SHA_3_224:
    case DIGEST_MODE::SHA_3_256:
    case DIGEST_MODE::SHA_3_384:
    case DIGEST_MODE::SHA_3_512:
        SHA_3_digest(digest_out, ctx);
        break;
    case DIGEST_MODE::SHA_3_SHAKE_128:
    case DIGEST_MODE::SHA_3_SHAKE_256:
        SHA_3_shake_digest(digest_out, ((SHA_3_Context*)ctx)->digestBytes, ctx);
        break;
    default:
        break;
    }
    return 0;
}

SHA_Context *SHA_Context_new(DIGEST_MODE mode)
{
    SHA_Context *ctx = NULL;
    switch (mode)
    {
    case DIGEST_MODE::SHA_1:
        ctx = new SHA_1_Context();
        break;
    case DIGEST_MODE::SHA_224:
        ctx = new SHA_224_Context();
        break;
    case DIGEST_MODE::SHA_256:
        ctx = new SHA_256_Context();
        break;
    case DIGEST_MODE::SHA_384:
        ctx = new SHA_384_Context();
        break;
    case DIGEST_MODE::SHA_512:
        ctx = new SHA_512_Context();
        break;
    case DIGEST_MODE::SHA_3_224:
    case DIGEST_MODE::SHA_3_256:
    case DIGEST_MODE::SHA_3_384:
    case DIGEST_MODE::SHA_3_512:
    case DIGEST_MODE::SHA_3_SHAKE_128:
    case DIGEST_MODE::SHA_3_SHAKE_256:
        ctx = new SHA_3_Context(mode);
        break;
    default:
        ctx = new SHA_1_Context();
        break;
    }
    return ctx;
}
