#include "inc/hash/sha.hpp"
#include "inc/logger.hpp"
#include <math.h>

#define DIGEST_OUT 160
#define SHA1_NUM_WORDS 16
#define SHA1_ROUNDS 80
#define SHA1_MASK 0x0000000f
#define SHA1_LEN_BYTES sizeof(uint64_t)
#define SHA1_ROTL(value, bits) (((value) << (bits)) | ((value) >> (sizeof(uint32_t)*8 - (bits))))


uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x&y) ^ (~x & z);
}

uint32_t Parity(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x&y) ^ (x&z) ^ (y&z);
}

uint32_t sha1_f(uint32_t x, uint32_t y, uint32_t z, int t)
{
    if(t <= 19)
        return Ch(x, y, z);
    else if(t <= 39)
        return Parity(x, y, z);
    else if(t <= 59)
        return Maj(x, y, z);
    else if(t <= 79)
        return Parity(x, y, z);
    else
        return -1;
}

uint32_t sha1_k(int t)
{    
    if(t <= 19)
        return 0x5a827999;
    else if(t <= 39)
        return 0x6ed9eba1;
    else if(t <= 59)
        return 0x8f1bbcdc;
    else if(t <= 79)
        return 0xca62c1d6;
    else
        return -1;
}

int SHA_1_Process(SHA_1_Context *ctx)
{
    /* Using circular queue schedular in accordance to FIPS 180-4 6.1.3 */
    uint32_t W[SHA1_NUM_WORDS];

    
    /* Step 1: Preparing the message schedular */
    for(int i = 0; i < SHA1_NUM_WORDS; i++)
        for(int j = 0; j < 4; j++)
        {
            W[i] <<= 8;
            W[i] |= ctx->block[i * sizeof(uint32_t) + j];
        }

    
    /* Step 2: Initialize working vars */
    uint32_t a = ctx->H[0];
    uint32_t b = ctx->H[1];
    uint32_t c = ctx->H[2];
    uint32_t d = ctx->H[3];
    uint32_t e = ctx->H[4];
    uint32_t tmp = 0;

    /* Step 3: Loop 80 rounds */
    for(int t = 0; t < SHA1_ROUNDS; t++)
    {
        uint s = t & SHA1_MASK;

        if(t >= 16)
        {
            W[s] = SHA1_ROTL( 
                W[ (s+13) & SHA1_MASK ]  ^
                W[ (s+8) & SHA1_MASK ] ^
                W[ (s+2)  & SHA1_MASK ] ^
                W[s],
                1
            );
        }

        tmp = SHA1_ROTL(a, 5) + sha1_f(b, c, d, t) + e + sha1_k(t) + W[s];
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = tmp;
       // printf("[Round %d]: A: %08X B: %08X C: %08X D: %08X E: %08X \n", t, a, b, c, d, e);
    }

    /* Step 4: compute intermediate hash value */
    ctx->H[0] = a + ctx->H[0];
    ctx->H[1] = b + ctx->H[1];
    ctx->H[2] = c + ctx->H[2];
    ctx->H[3] = d + ctx->H[3];
    ctx->H[4] = e + ctx->H[4];
    return 0;
}

int SHA_1_update(uint8_t *msg, size_t byMsg_len, SHA_1_Context *ctx)
{

    

    /* Make sure the bits are not exceeding 2^64 */
    
    if( (ctx->bMsg_len + (byMsg_len * 8)) >= pow(2, 64))
    {
        printf("\nERROR\n");
        return -1;
    }

   const uint8_t* src = (uint8_t*)msg;
   memset(ctx->block, 0, getSHABlockLengthByMode(ctx->mode));
   ctx->bMsg_len += (byMsg_len * 8);
   while(byMsg_len--)
   {
        ctx->block[ctx->blkPtr++] = *src++;
        if (ctx->blkPtr == getSHABlockLengthByMode(ctx->mode))
        {
            SHA_1_Process(ctx);
            ctx->blkPtr = 0;
        }
   }
    return 0;
}

int SHA_1_digest(uint8_t *digest_out, SHA_1_Context *ctx)
{

    /* Set the first bit to 1 (0b10000000) */
    ctx->block[ctx->blkPtr++] = 0x80;

    if(getSHABlockLengthByMode(ctx->mode) - ctx->blkPtr > 0)
        memset(ctx->block + ctx->blkPtr, 0, getSHABlockLengthByMode(ctx->mode) - ctx->blkPtr);

    /* Check if we can fit the message length into current block if not then process a new block */
    if(ctx->blkPtr > (getSHABlockLengthByMode(ctx->mode) - sizeof(uint64_t)) )
    {
        SHA_1_Process(ctx);
        ctx->blkPtr = 0;
        memset(ctx->block, 0, getSHABlockLengthByMode(ctx->mode));
    }
    uint64_t nSize = ctx->bMsg_len;

    for(int i = 1; i <= 4; i++)
    {
      /* Will pull the last byte of the size then remove it */
      ctx->block[getSHABlockLengthByMode(ctx->mode) - i] = nSize;
      nSize >>= 8;
    }

    SHA_1_Process(ctx);
    ctx->blkPtr = 0;

    for(int i = 0; i < getSHAReturnLengthByMode(SHA_1)/sizeof(ctx->H[i]); i++)
    {
        *(digest_out++) = ctx->H[i] >> 24;
        *(digest_out++) = ctx->H[i] >> 16;
        *(digest_out++) = ctx->H[i] >> 8;
        *(digest_out++) = ctx->H[i];
    }
    return 0;
}