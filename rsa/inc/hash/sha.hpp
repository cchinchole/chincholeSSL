#include <openssl/bn.h>
#include <stdio.h>
#include <memory.h>

#define SHA1_BLOCK_SIZE_BYTES 64
#define SHA2_384512_BLOCK_SIZE_BYTES 128

enum SHA_MODE {
    SHA_1,
    SHA_384,
    SHA_256,
    SHA_512,
    SHA_3_224,
    SHA_3_256,
    SHA_3_384,
    SHA_3_512,
};

class SHA_Context {
    private:
    public:
        uint64_t blkPtr = 0;    
        SHA_MODE mode = SHA_1;
        virtual void clear(){}
        virtual ~SHA_Context(){}
};

class SHA_3_Context : public SHA_Context {
   private:
   public:
      SHA_MODE mode = SHA_3_512;
      uint64_t rRate = 0;
      uint64_t bWidthSize = 0;
      uint64_t wLaneSize = 0;
      uint64_t lLogLane = 0;
      uint64_t b = 0;
      uint64_t c = 0;
      uint64_t nr = 0;
      SHA_3_Context(SHA_MODE mode)
      {
         
      }
};

class SHA_1_Context : public SHA_Context {
    public:
        uint64_t bMsg_len = 0;
        uint8_t block[SHA1_BLOCK_SIZE_BYTES];
        uint32_t H[5] = {
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
        };
     SHA_1_Context()
     {
        mode = SHA_1;
        bMsg_len = 0;
        blkPtr = 0;
        memset(block, 0, SHA1_BLOCK_SIZE_BYTES);
     }

     void clear()
     {
        bMsg_len = 0;
        blkPtr = 0;
        memset(block, 0, SHA1_BLOCK_SIZE_BYTES);

        uint64_t SHA_1_H0[5] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
        };

        for(int i = 0; i < 5; i++)
        {
            H[i] = SHA_1_H0[i];
        }
     }
};

class SHA_512_Context : public SHA_Context {
    public:
     uint64_t bMsg_len[2] = {0, 0};
     uint8_t block[SHA2_384512_BLOCK_SIZE_BYTES];
     uint64_t H[8] = {
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179
        };

     SHA_512_Context()
     {
        mode = SHA_512;
        bMsg_len[0] = 0;
        bMsg_len[1] = 0;
        blkPtr = 0;
        memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);
     }

     void clear()
     {
        bMsg_len[0] = 0;
        bMsg_len[1] = 0;
        blkPtr = 0;
        memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);

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

        for(int i = 0; i < 8; i++)
        {
            H[i] = SHA_512_H0[i];
        }
     }

     ~SHA_512_Context()
     {
     }
};


class SHA_384_Context : public SHA_Context {
    public:
     uint64_t bMsg_len[2] = {0, 0};
     uint8_t block[SHA2_384512_BLOCK_SIZE_BYTES];
     uint64_t H[8] = {
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4};
     SHA_384_Context()
     {
        mode = SHA_384;
        bMsg_len[0] = 0;
        bMsg_len[1] = 0;
        blkPtr = 0;
        memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);
     }

     void clear()
     {
        bMsg_len[0] = 0;
        bMsg_len[1] = 0;
        blkPtr = 0;
        memset(block, 0, SHA2_384512_BLOCK_SIZE_BYTES);

        uint64_t SHA_384_H0[8] = {
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4};


        for(int i = 0; i < 8; i++)
        {
            H[i] = SHA_384_H0[i];
        }
     }

     ~SHA_384_Context()
     {
     }
};

char *SHA_MODE_NAME(SHA_MODE mode);

int SHA_384512_update(uint8_t *msg, size_t byMsg_len, SHA_512_Context *ctx);
int SHA_384512_digest(uint8_t *digest_out, SHA_512_Context *ctx);
int SHA_384512_update(uint8_t *msg, size_t byMsg_len, SHA_384_Context *ctx);
int SHA_384512_digest(uint8_t *digest_out, SHA_384_Context *ctx);

int SHA_1_update(uint8_t *msg, size_t byMsg_len, SHA_1_Context *ctx);
int SHA_1_digest(uint8_t *digest_out, SHA_1_Context *ctx);


int SHA_3_update(uint8_t *msg, size_t byMsg_len, SHA_3_Context *ctx);

int sha_update(uint8_t *msg, size_t byMsg_len, SHA_Context *ctx);
int sha_digest(uint8_t *digest_out, SHA_Context *ctx);

SHA_Context *SHA_Context_new(SHA_MODE mode);

int getSHABlockLengthByMode(SHA_MODE mode);
int getSHAReturnLengthByMode(SHA_MODE mode);