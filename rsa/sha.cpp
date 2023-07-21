#include "inc/hash/sha.hpp"

int getSHABlockLengthByMode(SHA_MODE mode)
{
    switch(mode)
    {
        case SHA_1:
            return SHA1_BLOCK_SIZE_BYTES;
            break;
        case SHA_384:
            return SHA2_384512_BLOCK_SIZE_BYTES;
            break;
        case SHA_512:
            return SHA2_384512_BLOCK_SIZE_BYTES;
            break;
        default:
            return -1;
            break;
    }
    return -1;
}
int getSHAReturnLengthByMode(SHA_MODE mode)
{
    switch(mode)
    {
        case SHA_1:
            return 160/8;
            break;
        case SHA_384:
            return 384/8;
            break;
        case SHA_512:
            return 512/8;
            break;
        default:
            return -1;
            break;
    }
    return -1;
}
char *SHA_MODE_NAME(SHA_MODE mode)
{
    switch(mode)
    {
        case SHA_1:
            return "SHA_1";
        break;
        case SHA_256:
            return "SHA_256";
        break;
        case SHA_384:
            return "SHA_384";
        break;
        case SHA_512:
            return "SHA_512";
        break;
        default:
            return "";
        break;
    }
    return "";
}

int sha_update(uint8_t *msg, uint8_t byMsg_len, SHA_Context *ctx)
{
    switch(ctx->mode)
    {
        case SHA_1:
            SHA_1_update(msg, byMsg_len, (SHA_1_Context*)ctx);
            break;
        case SHA_512:
            SHA_512_update(msg, byMsg_len, (SHA_512_Context*)ctx);
            break;
        case SHA_384:
            SHA_512_update(msg, byMsg_len, (SHA_512_Context*)ctx);
            break;
    }
    return 0;
}
int sha_digest(uint8_t *digest_out, SHA_Context *ctx)
{  
    switch(ctx->mode)
    {
        case SHA_1:
            SHA_1_digest(digest_out, (SHA_1_Context*)ctx);
            break;
        case SHA_512:
            SHA_512_digest(digest_out, (SHA_512_Context*)ctx);
            break;
        case SHA_384:
            SHA_512_digest(digest_out, (SHA_512_Context*)ctx);
            break;
    }
    return 0;
}
