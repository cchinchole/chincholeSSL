#include "inc/hash/sha.hpp"
#include "inc/utils/logger.hpp"
#include <math.h>


int SHA_3_update(uint8_t *msg, size_t byMsg_len, SHA_3_Context *ctx)
{
    /* W can be thought of as how many words can be fit into the state array */
    /* First iterate over the bottom plane moving along the lane. Then start again one plane up. */
    /* Need to use a tail system in order to account for previous bits that were left open */
    /* bMsg_Len is now in bits instead of bytes. */
    uint64_t oTail = (8 - ctx->blkPtr) & 7;
    uint8_t *buf = msg;
    if(byMsg_len < oTail)
    {
        while(--byMsg_len)
            ctx->bufferedPortion |= (uint64_t)(*(buf++)) << ((ctx->blkPtr++) * 8);
        return 0;
    }

    if(oTail)
    {
        byMsg_len -= oTail;
        while(oTail--)
            ctx->bufferedPortion |= (uint64_t)(*(buf++)) << ((ctx->blkPtr++) * 8);

        ctx->sponge[ctx->spongeWordPtr] ^= ctx->bufferedPortion;
        ctx->blkPtr = 0;
        ctx->bufferedPortion = 0;
        if(ctx->spongeWordPtr++ == (SHA3_WORDS)- ctx->wordCap )
        {
            /* Process the sponge here, we have a full block */
            ctx->spongeWordPtr = 0;
        }
    }

    uint64_t words = byMsg_len / sizeof(uint64_t);
    uint64_t tail = byMsg_len - words * sizeof(uint64_t);



    return 0;
}