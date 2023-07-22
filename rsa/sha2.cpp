#include "inc/hash/sha.hpp"
#include "inc/utils/logger.hpp"
#include <math.h>

#define SHA2_NUM_WORDS 16
#define SHA2_ROUNDS 80

#define SHA2_512_LEN_BYTES 2*sizeof(uint64_t)

#define SHA2_ROTR(value, bits) (((value) >> (bits)) | ((value) << (sizeof(uint64_t)*8 - (bits))))
#define SHA2_ROTL(value, bits) (((value) << (bits)) | ((value) >> (sizeof(uint64_t)*8 - (bits))))
#define SHA2_SHR(value, bits) ((value) >> bits)

uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x&y) ^ (~x & z);
}

uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x&y) ^ (x&z) ^ (y&z);
}

uint64_t summat0_512(uint64_t x)
{
    return SHA2_ROTR(x, 28) ^ SHA2_ROTR(x, 34) ^ SHA2_ROTR(x, 39);
}

uint64_t summat1_512(uint64_t x)
{
    return SHA2_ROTR(x, 14) ^ SHA2_ROTR(x, 18) ^ SHA2_ROTR(x, 41);
}

uint64_t sigma0_512(uint64_t x)
{
    return SHA2_ROTR(x, 1) ^ SHA2_ROTR(x, 8) ^ SHA2_SHR(x, 7);
}

uint64_t sigma1_512(uint64_t x)
{
    return SHA2_ROTR(x, 19) ^ SHA2_ROTR(x, 61) ^ SHA2_SHR(x, 6);
}

uint64_t sha2_k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

int SHA_384512_process(SHA_384_Context *ctx)
{
    /* Using non circular queue this time */
    uint64_t W[SHA2_ROUNDS];

    /* Step 1: setup the message schedule */
    for(int i = 0; i < SHA2_NUM_WORDS; i++)
        for(int j = 0; j < sizeof(uint64_t); j++)
        {
            W[i] <<= 8;
            W[i] |= ctx->block[i * sizeof(uint64_t) + j];
        }

    for(int i = 16; i < SHA2_ROUNDS; i++)
    {
        W[i] =  sigma1_512(W[i-2])+
                W[i-7] +
                sigma0_512(W[i-15]) +
                W[i-16];
    }

    /* Step 2 init working vars */
    uint64_t a = ctx->H[0];
    uint64_t b = ctx->H[1];
    uint64_t c = ctx->H[2];
    uint64_t d = ctx->H[3];
    uint64_t e = ctx->H[4];
    uint64_t f = ctx->H[5];
    uint64_t g = ctx->H[6];
    uint64_t h = ctx->H[7];
    uint64_t tmp1 = 0;
    uint64_t tmp2 = 0;

    /* Step 3 loop */
    for(int t = 0; t < SHA2_ROUNDS; t++)
    {
        tmp1 = h + summat1_512(e)+Ch(e, f, g)+sha2_k[t]+W[t];
        tmp2 = summat0_512(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d+tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1+tmp2;
    }

    ctx->H[0] += a;
    ctx->H[1] += b;
    ctx->H[2] += c;
    ctx->H[3] += d;
    ctx->H[4] += e;
    ctx->H[5] += f;
    ctx->H[6] += g;
    ctx->H[7] += h;

    return 0;
}

int SHA_384512_update(uint8_t *msg, size_t byMsg_len, SHA_384_Context *ctx)
{  
    if(ctx->mode != SHA_512 && ctx->mode != SHA_384)
        return -1;

    uint64_t carry = byMsg_len * 8;
    uint64_t nextCarry = 0;
    for (int i = 0; i < 2; i++)
    {
        if (carry)
        {
            uint64_t initial = ctx->bMsg_len[i];
            ctx->bMsg_len[i] += carry;
            carry = 0;
            if (ctx->bMsg_len[i] < initial)
            {
                carry = 1;
            }
        }

        carry += nextCarry;
        nextCarry = 0;
    }



    const uint8_t* src = (uint8_t*)msg;
    memset(ctx->block, 0, getSHABlockLengthByMode(ctx->mode));
    while(byMsg_len--)
    {
            ctx->block[ctx->blkPtr++] = *src++;
            if (ctx->blkPtr == getSHABlockLengthByMode(ctx->mode))
            {
                SHA_384512_process(ctx);
                ctx->blkPtr = 0;
            }
    }
    return 0;
}

int SHA_384512_digest(uint8_t *digest_out, SHA_384_Context *ctx)
{

    if(ctx->mode != SHA_512 && ctx->mode != SHA_384)
        return -1;

    /* Set the first bit to 1 (0b10000000) */
    ctx->block[ctx->blkPtr++] = 0x80;

    if( getSHABlockLengthByMode(ctx->mode) - ctx->blkPtr > 0)
        memset(ctx->block + ctx->blkPtr, 0, getSHABlockLengthByMode(ctx->mode) - ctx->blkPtr);

    /* Check if we can fit the message length into current block if not then process a new block */
    if(ctx->blkPtr > (getSHABlockLengthByMode(ctx->mode) - SHA2_512_LEN_BYTES) )
    {
        SHA_384512_process(ctx);
        ctx->blkPtr = 0;
        memset(ctx->block, 0, getSHABlockLengthByMode(ctx->mode));
    }

    uint64_t nSize[2] = { ctx->bMsg_len[0], ctx->bMsg_len[1]};

    for(int i = ( SHA2_512_LEN_BYTES*8 ) - 1, sizeIdx = 0, byteCounter = 0; byteCounter < 16; i--, byteCounter++)
    {
      /* Will pull the last byte of the size then remove it. Will enumerate up to 16 bytes then swap to the other 64 bit int in the array */
       ctx->block[i] = nSize[sizeIdx];
       nSize[sizeIdx] >>= 8;
       if(i == getSHABlockLengthByMode(ctx->mode) - sizeof(uint64_t))
        sizeIdx++;
    }
    
    /* The final message with the length to process */
    SHA_384512_process(ctx);
    ctx->blkPtr = 0;

        
  
    for(int i = 0; i < getSHAReturnLengthByMode(ctx->mode)/sizeof(ctx->H[i]); i++)
    {
        *(digest_out++) = ctx->H[i] >> 56;
        *(digest_out++) = ctx->H[i] >> 48;
        *(digest_out++) = ctx->H[i] >> 40;
        *(digest_out++) = ctx->H[i] >> 32;
        *(digest_out++) = ctx->H[i] >> 24;
        *(digest_out++) = ctx->H[i] >> 16;
        *(digest_out++) = ctx->H[i] >> 8;
        *(digest_out++) = ctx->H[i];
    }

    return 0;
}

int SHA_384512_process(SHA_512_Context *ctx)
{
    /* Using non circular queue this time */
    uint64_t W[SHA2_ROUNDS];

    /* Step 1: setup the message schedule */
    for(int i = 0; i < SHA2_NUM_WORDS; i++)
        for(int j = 0; j < sizeof(uint64_t); j++)
        {
            W[i] <<= 8;
            W[i] |= ctx->block[i * sizeof(uint64_t) + j];
        }

    for(int i = 16; i < SHA2_ROUNDS; i++)
    {
        W[i] =  sigma1_512(W[i-2])+
                W[i-7] +
                sigma0_512(W[i-15]) +
                W[i-16];
    }

    /* Step 2 init working vars */
    uint64_t a = ctx->H[0];
    uint64_t b = ctx->H[1];
    uint64_t c = ctx->H[2];
    uint64_t d = ctx->H[3];
    uint64_t e = ctx->H[4];
    uint64_t f = ctx->H[5];
    uint64_t g = ctx->H[6];
    uint64_t h = ctx->H[7];
    uint64_t tmp1 = 0;
    uint64_t tmp2 = 0;

    /* Step 3 loop */
    for(int t = 0; t < SHA2_ROUNDS; t++)
    {
        tmp1 = h + summat1_512(e)+Ch(e, f, g)+sha2_k[t]+W[t];
        tmp2 = summat0_512(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d+tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1+tmp2;
    }

    ctx->H[0] += a;
    ctx->H[1] += b;
    ctx->H[2] += c;
    ctx->H[3] += d;
    ctx->H[4] += e;
    ctx->H[5] += f;
    ctx->H[6] += g;
    ctx->H[7] += h;

    return 0;
}

int SHA_384512_update(uint8_t *msg, size_t byMsg_len, SHA_512_Context *ctx)
{  
    if(ctx->mode != SHA_512 && ctx->mode != SHA_384)
        return -1;

    uint64_t carry = byMsg_len * 8;
    uint64_t nextCarry = 0;
    for (int i = 0; i < 2; i++)
    {
        if (carry)
        {
            uint64_t initial = ctx->bMsg_len[i];
            ctx->bMsg_len[i] += carry;
            carry = 0;
            if (ctx->bMsg_len[i] < initial)
            {
                carry = 1;
            }
        }

        carry += nextCarry;
        nextCarry = 0;
    }



    const uint8_t* src = (uint8_t*)msg;
    memset(ctx->block, 0, getSHABlockLengthByMode(ctx->mode));
    while(byMsg_len--)
    {
            ctx->block[ctx->blkPtr++] = *src++;
            if (ctx->blkPtr == getSHABlockLengthByMode(ctx->mode))
            {
                SHA_384512_process(ctx);
                ctx->blkPtr = 0;
            }
    }
    return 0;
}

int SHA_384512_digest(uint8_t *digest_out, SHA_512_Context *ctx)
{

    if(ctx->mode != SHA_512 && ctx->mode != SHA_384)
        return -1;

    /* Set the first bit to 1 (0b10000000) */
    ctx->block[ctx->blkPtr++] = 0x80;

    if( getSHABlockLengthByMode(ctx->mode) - ctx->blkPtr > 0)
        memset(ctx->block + ctx->blkPtr, 0, getSHABlockLengthByMode(ctx->mode) - ctx->blkPtr);

    /* Check if we can fit the message length into current block if not then process a new block */
    if(ctx->blkPtr > (getSHABlockLengthByMode(ctx->mode) - SHA2_512_LEN_BYTES) )
    {
        SHA_384512_process(ctx);
        ctx->blkPtr = 0;
        memset(ctx->block, 0, getSHABlockLengthByMode(ctx->mode));
    }

    uint64_t nSize[2] = { ctx->bMsg_len[0], ctx->bMsg_len[1]};

    for(int i = ( SHA2_512_LEN_BYTES*8 ) - 1, sizeIdx = 0, byteCounter = 0; byteCounter < 16; i--, byteCounter++)
    {
      /* Will pull the last byte of the size then remove it. Will enumerate up to 16 bytes then swap to the other 64 bit int in the array */
       ctx->block[i] = nSize[sizeIdx];
       nSize[sizeIdx] >>= 8;
       if(i == getSHABlockLengthByMode(ctx->mode) - sizeof(uint64_t))
        sizeIdx++;
    }
    
    /* The final message with the length to process */
    SHA_384512_process(ctx);
    ctx->blkPtr = 0;

        
  
    for(int i = 0; i < getSHAReturnLengthByMode(ctx->mode)/sizeof(ctx->H[i]); i++)
    {
        *(digest_out++) = ctx->H[i] >> 56;
        *(digest_out++) = ctx->H[i] >> 48;
        *(digest_out++) = ctx->H[i] >> 40;
        *(digest_out++) = ctx->H[i] >> 32;
        *(digest_out++) = ctx->H[i] >> 24;
        *(digest_out++) = ctx->H[i] >> 16;
        *(digest_out++) = ctx->H[i] >> 8;
        *(digest_out++) = ctx->H[i];
    }

    return 0;
}