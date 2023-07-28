#include "inc/hash/sha.hpp"
#include "inc/utils/logger.hpp"
#include <math.h>

#define SHA256_NUM_WORDS 16
#define SHA256_ROUNDS 64
#define SHA256_MASK 0x0000000f
#define SHA256_LEN_BYTES sizeof(uint64_t)
#define SHA256_ROTR(value, bits) (((value) >> (bits)) | ((value) << (sizeof(uint32_t)*8 - (bits))))
#define SHA256_SHR(value, bits) ((value) >> bits)


uint32_t Ch2(uint32_t x, uint32_t y, uint32_t z)
{
    return (x&y) ^ (~x & z);
}

uint32_t Maj2(uint32_t x, uint32_t y, uint32_t z)
{
    return (x&y) ^ (x&z) ^ (y&z);
}

uint32_t summat0_256(uint32_t x)
{
    return SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22);
}

uint32_t summat1_256(uint32_t x)
{
    return SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25);
}

uint32_t sigma0_256(uint32_t x)
{
    return SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ SHA256_SHR(x, 3);
}

uint32_t sigma1_256(uint32_t x)
{
    return SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ SHA256_SHR(x, 10);
}

uint32_t SHA256_k[SHA256_ROUNDS]
{    
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

int SHA_224256_Process(SHA_Context *ctx)
{
    /* Using circular queue schedular in accordance to FIPS 180-4 6.1.3 */
    uint32_t W[SHA256_ROUNDS];
    uint8_t *block = (uint8_t*)(ctx->blockP);
    uint32_t *H = (uint32_t*)(ctx->HP);

    /* Step 1: setup the message schedule */
    for(int i = 0; i < SHA256_NUM_WORDS; i++)
        for(int j = 0; j < sizeof(uint32_t); j++)
        {
            char z =  block[i * sizeof(uint32_t) + j];
            W[i] <<= 8;
            W[i] |= block[i * sizeof(uint32_t) + j];
        }

    for(int i = 16; i < SHA256_ROUNDS; i++)
    {
        W[i] =  sigma1_256(W[i-2])+
                W[i-7] +
                sigma0_256(W[i-15]) +
                W[i-16];
    }


    
    /* Step 2: Initialize working vars */
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];
    uint32_t tmp1 = 0;
    uint32_t tmp2 = 0;

    /* Step 3: Loop 63 rounds */
    for(int t = 0; t < SHA256_ROUNDS; t++)
    {
        tmp1 = h + summat1_256(e) + Ch2(e, f, g) + SHA256_k[t] + W[t];
        tmp2 = summat0_256(a) + Maj2(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1+tmp2;
        //printf("[Round %d]: A: %08X B: %08X C: %08X D: %08X E: %08X \nF: %08X \nG: %08X \nH: %08X \n", t, a, b, c, d, e, f, g, h);
    }

    /* Step 4: compute intermediate hash value */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
    return 0;
}

int SHA_224256_update(uint8_t *msg, size_t byMsg_len, SHA_Context *ctx)
{
    uint64_t* bMsg_len = ((uint64_t*)ctx->bMsg_lenP);
    uint8_t *block = (uint8_t*)(ctx->blockP);
    /* Make sure the bits are not exceeding 2^64 */
    if( ( *bMsg_len + (byMsg_len * 8)) >= pow(2, 64))
        return -1;

   /* Clear the block with 0's then copy up to 64 bytes of a message into the block. If we hit 64 then process this message and continue. */
   const uint8_t* src = (uint8_t*)msg;
   memset(block, 0, getSHABlockLengthByMode(ctx->mode));
    *bMsg_len += (byMsg_len * 8);
   while(byMsg_len--)
   {
        block[ctx->blockCur++] = *src++;
        if (ctx->blockCur == getSHABlockLengthByMode(ctx->mode))
        {
            SHA_224256_Process(ctx);
            ctx->blockCur = 0;
        }
   }
    return 0;
}

int SHA_224256_digest(uint8_t *digest_out, SHA_Context *ctx)
{

    uint8_t *block = (uint8_t*)(ctx->blockP);
    uint32_t *H = (uint32_t*)(ctx->HP);

    /* Set the first bit to 1 (0b10000000) */
    block[ctx->blockCur++] = 0x80;

    if(getSHABlockLengthByMode(ctx->mode) - ctx->blockCur > 0)
        memset(block + ctx->blockCur, 0, getSHABlockLengthByMode(ctx->mode) - ctx->blockCur);

    /* Check if we can fit the message length into current block if not then process a new block */
    if(ctx->blockCur > (getSHABlockLengthByMode(ctx->mode) - sizeof(uint64_t)) )
    {
        SHA_224256_Process(ctx);
        ctx->blockCur = 0;
        memset(block, 0, getSHABlockLengthByMode(ctx->mode));
    }
    uint64_t nSize =  *((uint32_t*)ctx->bMsg_lenP);

    for(int i = 1; i <= 4; i++)
    {
      /* Will pull the last byte of the size then remove it */
      block[getSHABlockLengthByMode(ctx->mode) - i] = nSize;
      nSize >>= 8;
    }

    /* The final message with the length to process */
    SHA_224256_Process(ctx);
    ctx->blockCur = 0;

    for(int i = 0; i < getSHAReturnLengthByMode(ctx->mode)/sizeof(H[i]); i++)
    {
        *(digest_out++) = H[i] >> 24;
        *(digest_out++) = H[i] >> 16;
        *(digest_out++) = H[i] >> 8;
        *(digest_out++) = H[i];
    }
    return 0;
}