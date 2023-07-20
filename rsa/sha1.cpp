#include "inc/hash/sha.hpp"
#include "inc/logger.hpp"
#include <math.h>

#define DIGEST_OUT 160
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

int sha1_process(SHA1_Context *ctx)
{
    /* Using circular queue schedular in accordance to FIPS 180-4 6.1.3 */
    uint32_t W[SHA1_NUM_WORDS];

    
    /* Step 1: Preparing the message schedular */
    for(int i = 0; i < SHA1_NUM_WORDS; i++)
        for(int j = 0; j < 4; j++)
        {
            W[i] <<= 8;
            W[i] |= ctx->state[i * sizeof(uint32_t) + j];
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

int sha1_update(uint8_t *msg, uint8_t byMsg_len, SHA1_Context *ctx)
{
    uint msgPtr = 0;

    /* Make sure the bits are not exceeding 2^64 */
    if( (ctx->bMsg_len + (byMsg_len * 8)) >= pow(2, 64))
        return -1;

    while ((msgPtr < byMsg_len))
    {
        /* Check if we are closer to end of block or end of message*/
        int blockSize = 0;
        if(byMsg_len - msgPtr < SHA1_BLOCK_SIZE_BYTES - ctx->statePtr)
            blockSize = byMsg_len - msgPtr;
        else
            blockSize = SHA1_BLOCK_SIZE_BYTES - ctx->statePtr;

        memcpy(ctx->state + ctx->statePtr, msg + msgPtr, blockSize);
        msgPtr += blockSize;
        ctx->statePtr += blockSize;

        if(ctx->statePtr == SHA1_BLOCK_SIZE_BYTES)
        {
            /* Overlapping the block so process this information and await new */
            sha1_process(ctx);
            ctx->statePtr = 0;
        }
    }
    
    ctx->bMsg_len += (byMsg_len * 8);
    return 0;
}

int sha1_digest(unsigned char *digest_out, SHA1_Context *ctx)
{

    /* Set the first bit to 1 (0b10000000) */
    ctx->state[ctx->statePtr++] = 0x80;

    if(SHA1_BLOCK_SIZE_BYTES - ctx->statePtr > 0)
        memset(ctx->state + ctx->statePtr, 0, SHA1_BLOCK_SIZE_BYTES - ctx->statePtr);

    /* Check if we can fit the message length into current block if not then process a new block */
    if(ctx->statePtr >= (SHA1_BLOCK_SIZE_BYTES - sizeof(uint64_t)) )
    {
        sha1_process(ctx);
        ctx->statePtr = 0;
        memset(ctx->state, 0, SHA1_BLOCK_SIZE_BYTES);
    }

    uint64_t nSize = ctx->bMsg_len;

    for(int i = ( sizeof(uint64_t)*8 ) - 1; nSize; i--)
    {
        /* Will pull the last byte of the size then remove it */
        ctx->state[i] = nSize; 
        nSize >>= 8;
    }

    sha1_process(ctx);
    ctx->statePtr = 0;

    snprintf ( (char*)digest_out, 41, "%08X%08X%08X%08X%08X",
              ctx->H[0],ctx->H[1],ctx->H[2],ctx->H[3],ctx->H[4]);
        

    return 0;
}