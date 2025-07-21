#include "internal/sha.hpp"
#include <math.h>

#define SHA1_NUM_WORDS 16
#define SHA1_ROUNDS 80
#define SHA1_MASK 0x0000000f
#define SHA1_LEN_BYTES sizeof(uint64_t)
#define SHA1_ROTL(value, bits)                                                 \
    (((value) << (bits)) | ((value) >> (sizeof(uint32_t) * 8 - (bits))))

uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

uint32_t parity(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t sha1_f(uint32_t x, uint32_t y, uint32_t z, int t)
{
    if (t <= 19)
        return ch(x, y, z);
    else if (t <= 39)
        return parity(x, y, z);
    else if (t <= 59)
        return maj(x, y, z);
    else if (t <= 79)
        return parity(x, y, z);
    else
        return -1;
}

uint32_t sha1_k(int t)
{
    if (t <= 19)
        return 0x5a827999;
    else if (t <= 39)
        return 0x6ed9eba1;
    else if (t <= 59)
        return 0x8f1bbcdc;
    else if (t <= 79)
        return 0xca62c1d6;
    else
        return -1;
}

int sha1_process(ShaContext *ctx)
{
    /* Using circular queue schedular in accordance to FIPS 180-4 6.1.3 */
    uint32_t W[SHA1_NUM_WORDS];
    uint8_t *block = (uint8_t *)(ctx->pblock_);
    uint32_t *H = (uint32_t *)(ctx->ph_);

    /* Step 1: Preparing the message schedular */
    for (int i = 0; i < SHA1_NUM_WORDS; i++)
        for (int j = 0; j < 4; j++)
        {
            W[i] <<= 8;
            W[i] |= block[i * sizeof(uint32_t) + j];
        }

    /* Step 2: Initialize working vars */
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t tmp = 0;

    /* Step 3: Loop 80 rounds */
    for (int t = 0; t < SHA1_ROUNDS; t++)
    {
        uint s = t & SHA1_MASK;

        if (t >= 16)
        {
            W[s] = SHA1_ROTL(W[(s + 13) & SHA1_MASK] ^ W[(s + 8) & SHA1_MASK] ^
                                 W[(s + 2) & SHA1_MASK] ^ W[s],
                             1);
        }

        tmp = SHA1_ROTL(a, 5) + sha1_f(b, c, d, t) + e + sha1_k(t) + W[s];
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = tmp;
        // printf("[Round %d]: A: %08X B: %08X C: %08X D: %08X E: %08X \n", t,
        // a, b, c, d, e);
    }

    /* Step 4: compute intermediate hash value */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    return 0;
}

int sha1_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx)
{
    uint64_t *bMsg_len = ((uint64_t *)ctx->pmsg_len_);
    uint8_t *block = (uint8_t *)(ctx->pblock_);
    /* Make sure the bits are not exceeding 2^64 */
    if ((*bMsg_len + (byMsg_len * 8)) >= pow(2, 64))
        return -1;

    /* Clear the block with 0's then copy up to 64 bytes of a message into the
     * block. If we hit 64 then process this message and continue. */
    const uint8_t *src = (uint8_t *)msg;
    memset(block, 0, get_block_length(ctx->mode_));
    *bMsg_len += (byMsg_len * 8);
    while (byMsg_len--)
    {
        block[ctx->block_cursor_++] = *src++;
        if (ctx->block_cursor_ == get_block_length(ctx->mode_))
        {
            sha1_process(ctx);
            ctx->block_cursor_ = 0;
        }
    }
    return 0;
}

int sha1_digest(uint8_t *digest_out, ShaContext *ctx)
{

    uint8_t *block = (uint8_t *)(ctx->pblock_);
    uint32_t *H = (uint32_t *)(ctx->ph_);

    /* Set the first bit to 1 (0b10000000) */
    block[ctx->block_cursor_++] = 0x80;

    if (get_block_length(ctx->mode_) - ctx->block_cursor_ > 0)
        memset(block + ctx->block_cursor_, 0,
               get_block_length(ctx->mode_) - ctx->block_cursor_);

    /* Check if we can fit the message length into current block if not then
     * process a new block */
    if (ctx->block_cursor_ > (get_block_length(ctx->mode_) - sizeof(uint64_t)))
    {
        sha1_process(ctx);
        ctx->block_cursor_ = 0;
        memset(block, 0, get_block_length(ctx->mode_));
    }
    uint64_t nSize = *((uint32_t *)ctx->pmsg_len_);

    for (int i = 1; i <= 4; i++)
    {
        /* Will pull the last byte of the size then remove it */
        block[get_block_length(ctx->mode_) - i] = nSize;
        nSize >>= 8;
    }

    /* The final message with the length to process */
    sha1_process(ctx);
    ctx->block_cursor_ = 0;

    for (int i = 0; i < get_return_length(ctx->mode_) / sizeof(H[i]); i++)
    {
        *(digest_out++) = H[i] >> 24;
        *(digest_out++) = H[i] >> 16;
        *(digest_out++) = H[i] >> 8;
        *(digest_out++) = H[i];
    }
    return 0;
}
