#include "inc/hash/sha.hpp"
#include "inc/utils/logger.hpp"
#include <math.h>

#define KECCAKF_ROUNDS 24

#define SHA3_ROTL(x, y) (((x) << (y)) | ((x) >> ((sizeof(uint64_t) * 8) - (y))))

/* Table 2 Keccak, Table 2 SP202 */
uint64_t SHA3_RHO_K[5][5] =
    {
        {0, 1, 190, 28, 91},   /* starting from j = 0, i = 0 then j = 0, i = 1 */
        {36, 300, 6, 55, 276}, /* starting from j = 1, i = 0 then j = 1, i = 1 */
        {3, 10, 171, 153, 231},
        {105, 45, 15, 21, 136},
        {210, 66, 253, 120, 78}};

/* Table 1 Keccak */
uint64_t SHA3_RC_K[24] =
    {
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008};

/*
Keccak functions were made using SP202 description and keccak's pseudo code for computational math.
*/

int SHA3_keccakTHETA(uint64_t sponge[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR])
{
    uint64_t C[SHA3_SPONGE_ARR];

    memset(C, 0, SHA3_SPONGE_ARR * sizeof(uint64_t));
    /* Move in the X direction then add 5 to access x,[y],z; optimized to shorten from loop(x,y) */
    /* C[x,z] [x,0,z] ^ [x,1,z] ... 4 */
    /* D[x,z] = C[ (x-1)mod5, z ] ^ C[(x+1) mod 5, (z-1)mod w ] */
    for (int i = 0; i < SHA3_SPONGE_ARR; i++)
        for (int j = 0; j < SHA3_SPONGE_ARR; j++)
            C[i] ^= sponge[j][i];

    /* Adding 4 to move through the Z axis */
    /* Using a rotation to calculate (z-1) mod w */
    for (int i = 0; i < SHA3_SPONGE_ARR; i++)
    {
        /* Storing D in a single uint64_t instead of array to calculate sponge values instantly instead of in another loop */
        uint64_t D = C[(i + 4) % 5] ^ SHA3_ROTL(C[(i + 1) % 5], 1);
        /* For all triples (x,y,z) A[x,y,z] ^ D[x,z] */
        for (int j = 0; j < SHA3_SPONGE_ARR; j++)
            sponge[j][i] ^= D;
    }
    return 0;
}

int SHA3_keccakRHOandPI(uint64_t B[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR], uint64_t sponge[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR])
{
    /* RHO and PI are done in the same loop for optimization. */
    /* RHO: For all Z, 0<z<w let A' [0,0,z] = A[0,0,z]*/

    /* Combined the two functions into one operation. */
    /* RHO Dictates:    A'[x,y,z] = A[x,y, (z-1(t+1)(t+2)/2 mod w)] */
    /* Using Table 2 of SP202 for SHA3 RHO's Constants */
    /* PI Dictates:     A'[x,y,z] = A[(x+3y) mod 5,x,z ]*/
    for (int i = 0; i < SHA3_SPONGE_ARR; i++)
        for (int j = 0; j < SHA3_SPONGE_ARR; j++)
            B[(2 * i + 3 * j) % 5][j] = SHA3_ROTL(sponge[j][i], SHA3_RHO_K[j][i]);
    return 0;
}

int SHA3_keccakCHI(uint64_t B[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR], uint64_t sponge[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR])
{
    /* A'[x,y,z] = A[x,y,z] ^  ((A[ (x+1) mod 5,y,z ] ^ 1) * A[ (x+2) mod 5,y,z ]) */
    /* Can do the second operand of ^ as the compliment of B AND'd with B */
    for (int i = 0; i < SHA3_SPONGE_ARR; i++)
        for (int j = 0; j < SHA3_SPONGE_ARR; j++)
            sponge[j][i] = B[j][i] ^ (~B[j][(i + 1) % 5] & B[j][(i + 2) % 5]);

    return 0;
}

int SHA3_keccakIOTA(uint64_t *spongeOrigin, int iteration)
{
    /* A[0,0] ^= RC */
    *spongeOrigin ^= SHA3_RC_K[iteration];
    return 0;
}

int SHA3_keccakf(uint64_t sponge[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR])
{
    uint64_t t, C[SHA3_SPONGE_ARR], B[SHA3_SPONGE_ARR][SHA3_SPONGE_ARR];

    memset(B, 0, SHA3_WORDS * sizeof(uint64_t));

    for (int i = 0; i < KECCAKF_ROUNDS; i++)
    {
        SHA3_keccakTHETA(sponge);
        SHA3_keccakRHOandPI(B, sponge);
        SHA3_keccakCHI(B, sponge);
        SHA3_keccakIOTA(&sponge[0][0], i);
    }
    return 0;
}

int SHA_3_update(uint8_t *msg, size_t byMsg_len, SHA_3_Context *ctx)
{
    if(!msg || byMsg_len == 0)
        return -1;
    for (int i = 0; i < byMsg_len; i++)
    {
        ctx->sponge.bytes[ctx->blockCur++] ^= ((const uint8_t *)msg)[i];
        if (ctx->blockCur >= ctx->r)
        {
            SHA3_keccakf(ctx->sponge.words);
            ctx->blockCur = 0;
        }
    }
    return 0;
}

int SHA_3_digest(uint8_t *digestOut, SHA_3_Context *ctx)
{
    /* Padding and setting the last bits to 11 */
    ctx->sponge.bytes[ctx->blockCur] ^= 0x06;
    ctx->sponge.bytes[ctx->r - 1] ^= 0x80;
    SHA3_keccakf(ctx->sponge.words);

    for (int i = 0; i < ctx->digestBytes; i++)
    {
        ((uint8_t *)digestOut)[i] = ctx->sponge.bytes[i];
    }

    return 0;
}

int SHA_3_xof(SHA_3_Context *ctx)
{
    ctx->sponge.bytes[ctx->blockCur] ^= 0x1F;
    ctx->sponge.bytes[ctx->r - 1] ^= 0x80;
    SHA3_keccakf(ctx->sponge.words);
    ctx->blockCur = 0;
    return 0;
}

int SHA_3_shake_digest(uint8_t *digestOut, size_t digestLen, SHA_3_Context *ctx)
{
    int j = ctx->blockCur;
    for (int i = 0; i < digestLen; i++)
    {
        if (j >= ctx->r)
        {
            SHA3_keccakf(ctx->sponge.words);
            j = 0;
        }
        ((uint8_t *)digestOut)[i] = ctx->sponge.bytes[j++];
    }

    ctx->blockCur = j;
    return 0;
}
