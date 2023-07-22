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
        case SHA_3_224:
            return 224/8;
            break;
        case SHA_3_256:
            return 256/8;
            break;
        case SHA_3_384:
            return 384/8;
            break;
        case SHA_3_512:
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
            return (char*)"SHA_1";
        break;
        case SHA_256:
            return (char*)"SHA_256";
        break;
        case SHA_384:
            return (char*)"SHA_384";
        break;
        case SHA_512:
            return (char*)"SHA_512";
        break;
        default:
            return (char*)"";
        break;
    }
    return (char*)"";
}
int sha_update(uint8_t *msg, size_t byMsg_len, SHA_Context *ctx)
{
    switch(ctx->mode)
    {
        case SHA_1:
            SHA_1_update(msg, byMsg_len, (SHA_1_Context*)ctx);
            break;
        case SHA_512:
            SHA_384512_update(msg, byMsg_len, (SHA_512_Context*)ctx);
            break;
        case SHA_384:
            SHA_384512_update(msg, byMsg_len, (SHA_384_Context*)ctx);
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
            SHA_384512_digest(digest_out, (SHA_512_Context*)ctx);
            break;
        case SHA_384:
            SHA_384512_digest(digest_out, (SHA_384_Context*)ctx);
            break;
    }
    return 0;
}

SHA_Context *SHA_Context_new(SHA_MODE mode)
{
  SHA_Context *ctx = NULL;
  switch(mode)
  {
    case SHA_1:
      ctx = new SHA_1_Context;
      break;
    case SHA_384:
      ctx = new SHA_384_Context;
      break;
    case SHA_512:
      ctx = new SHA_512_Context;
      break;
    case SHA_3_512:
      ctx = new SHA_3_Context(mode);
      break;
    default:
      ctx = new SHA_1_Context;
      break;
  }
  return ctx;
}