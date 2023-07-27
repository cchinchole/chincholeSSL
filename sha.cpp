#include "inc/hash/sha.hpp"

uint32_t SHA_1_H0[5] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
};

uint32_t SHA_256_H0[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
};

uint64_t SHA_512_H0[8] = {
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179
};
uint64_t SHA_384_H0[8] = {
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4
};

SHA_3_Context::SHA_3_Context(SHA_MODE mode)
      {
         this->mode = mode;
         switch(mode)
         {
            case SHA_3_224:
               this->digestBytes = 224/8;
            break;
            case SHA_3_256:
               this->digestBytes = 256/8;
            break;
            case SHA_3_384:
               this->digestBytes = 384/8;
            break;
            case SHA_3_512:
               this->digestBytes = 512/8;
            break;
            default:
               this->digestBytes = -1;
            break;
         }
         memset(sponge.words, 0, SHA3_WORDS);
         this->blockCur = 0;
         r = (SHA3_WORDS*8) - (2* (digestBytes) );
      }

SHA_1_Context::SHA_1_Context()
{
        /* Set the pointers */
        bMsg_lenP = &bMsg_len;
        HP = &H;
        blockP = &block;

        mode = SHA_1;
        bMsg_len = 0;
        blockCur = 0;
        memset(block, 0, SHA1_BLOCK_SIZE_BYTES);
}
void SHA_1_Context::clear()
{
        bMsg_len = 0;
        blockCur = 0;
        memset(block, 0, SHA1_BLOCK_SIZE_BYTES);
        for(int i = 0; i < 5; i++)
        {
            H[i] = SHA_1_H0[i];
        }
}


SHA_512_Context::SHA_512_Context()
{
        /* Set the pointers */
        bMsg_lenP = &bMsg_len;
        HP = &H;
        blockP = &block;

        mode = SHA_512;
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


        for(int i = 0; i < 8; i++)
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

        mode = SHA_384;
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
        for(int i = 0; i < 8; i++)
        {
            H[i] = SHA_384_H0[i];
        }
     }

int getSHABlockLengthByMode(SHA_MODE mode)
{
    switch(mode)
    {
        case SHA_1:
            return SHA1_BLOCK_SIZE_BYTES;
            break;
        case SHA_256:
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
        case SHA_256:
            return 256/8;
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
        case SHA_3_224:
            return (char*)"SHA_3_224";
        break;
        case SHA_3_256:
            return (char*)"SHA_3_256";
        break;
        case SHA_3_384:
            return (char*)"SHA_3_384";
        break;
        case SHA_3_512:
            return (char*)"SHA_3_512";
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
        case SHA_3_224:
        case SHA_3_256:
        case SHA_3_384:
        case SHA_3_512:
            SHA_3_update(msg, byMsg_len, (SHA_3_Context*)ctx);
            break;        
        default:
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
        case SHA_3_224:
        case SHA_3_256:
        case SHA_3_384:
        case SHA_3_512:
            SHA_3_digest(digest_out, (SHA_3_Context*)ctx);
            break;
        default:
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
      ctx = new SHA_1_Context();
      break;
    case SHA_384:
      ctx = new SHA_384_Context();
      break;
    case SHA_512:
      ctx = new SHA_512_Context();
      break;
    case SHA_3_224:
    case SHA_3_256:
    case SHA_3_384:
    case SHA_3_512:
      ctx = new SHA_3_Context(mode);
      break;
    default:
      ctx = new SHA_1_Context();
      break;
  }
  return ctx;
}