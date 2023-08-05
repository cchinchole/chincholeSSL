#include "inc/crypto/aes.hpp"
#include <stdio.h>
#include <memory>
#include "inc/utils/bytes.hpp"
#include "malloc.h"

/* FIPS 197 5.1.1 table 4 */
const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* FIPS 197 5.2 - Table 5 added 0x00 as padding */
const uint8_t rCon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};

/* FOR (nk,nr) AES256: 8,14 , 192: 6,12; 128: 4, 10*/
int getNR(AES_MODE mode)
{
    switch(mode)
    {
        case AES_CBC_128:
            return 10;
        break;
        case AES_CBC_192:
            return 12;
        break;
        case AES_CBC_256:
            return 14;
        break;
        default:
            return -1;
        break;
    }
    return -1;
}

int getNK(AES_MODE mode)
{
    switch(mode)
    {
        case AES_CBC_128:
            return 4;
        break;
        case AES_CBC_192:
            return 6;
        break;
        case AES_CBC_256:
            return 8;
        break;
        default:
            return -1;
        break;
    }
    return -1;
}

int rotateWord(uint8_t *a)
{
    uint8_t temp[4];
    for(int i = 0; i < 3;i ++)
        temp[i] = a[i+1];
    temp[3] = a[0];

    for(int i = 0 ;i < 4; i++)
        a[i] = temp[i];
    return 0;
}

int subWord(uint8_t *a)
{
    uint8_t temp[4];
    for(int i = 0; i < 4; i++)
        temp[i] = sbox[ a[i] ];

    for(int i = 0 ;i < 4; i++)
        a[i] = temp[i];
    return 0;
}

int subWord(uint8_t state[4][4])
{


    for(int i = 0 ;i < 4; i++)
        for(int j = 0 ;j < 4; j++)
        state[i][j] = sbox[ state[i][j] ];
    return 0;
}

int shiftRows(uint8_t state[4][4])
{
    
    uint8_t temp;
    temp = state[0][1];
    for(int i = 0; i < 3; i++)
    {
        state[i][1] = state[i+1][1];
    }
    state[3][1] = temp;

    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    temp = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
    
    return 0;
}

uint8_t xtime(uint8_t x)
{
    return (x<<1)^ (((x>>7) & 1) * 0x1b);
}

int mixColumns(uint8_t state[4][4])
{
    for(int i = 0 ; i < 4; i++)
    {
        uint8_t tmp = state[i][0];
        uint8_t tmp2 = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];

        uint8_t tmp3 = state[i][0] ^ state[i][1];
        tmp3 = xtime(tmp3);
        state[i][0] ^= tmp3 ^ tmp2;

        tmp3 = state[i][1] ^ state[i][2];
        tmp3 = xtime(tmp3);
        state[i][1] ^= tmp3 ^ tmp2;

        tmp3 = state[i][2] ^ state[i][3];
        tmp3 = xtime(tmp3);
        state[i][2] ^= tmp3 ^ tmp2;

        tmp3 = state[i][3] ^ tmp;
        tmp3 = xtime(tmp3);
        state[i][3] ^= tmp3 ^ tmp2;
    }
    return 0;
}

char *stateToString(uint8_t state[nB][nB])
{

    char *dest = (char*) malloc(2*AES_BlockSize + 1);
    if (!dest) return NULL;

    char *p = dest;
    for (size_t i = 0;  i < nB;  i++)
        for (size_t j = 0;  j < nB;  j++)
            p += sprintf((char*)p, "%02hhX", (state[j][i]) );
    return dest;
}

char *roundkeyToString(const uint8_t *w)
{

    char *dest = (char*) malloc(2*AES_BlockSize + 1);
    if (!dest) return NULL;

    char *p = dest;
    for (size_t i = 0;  i < nB;  i++)
        for (size_t j = 0;  j < nB;  j++)
            p += sprintf((char*)p, "%02hhX", (w[ (j*nB) + i]) );
    return dest;
}

int FIPS_197_5_2_KeyExpansion(AES_CTX *ctx, uint8_t *key)
{
    int retCode = 0;
    uint8_t temp[4];

    for(int i = 0; i <= getNK(ctx->mode)-1; i++)
        for(int j = 0; j < 4; j++)
            ctx->w[ (i*4) + j] = key[ (i*4) + j];

    for(int i = 0; i <= getNK(ctx->mode)-1; i++)
        for(int j = 0; j < 4; j++)
            printf("%02x", ctx->w[ (i*4) + j]);
    printf(" is the input to w\n");
    
    
    for(int i = getNK(ctx->mode); i <= 4*getNR(ctx->mode)+3; i++)
    {
        for(int j = 0 ; j < 4; j++)
            temp[j] = ctx->w[ (i-1)*4 + j];

            printf("[Round %d] temp: ", i);
            for(int j = 0 ; j < 4; j++)
                 printf("%02x", temp[j]);
            printf(" ");
       

        if(i % getNK(ctx->mode) == 0)
        {
            rotateWord(temp);
            
            printf("after rotate: ");
            for(int j = 0 ; j < 4; j++)
                 printf("%02x", temp[j]);
            printf(" ");
            
            subWord(temp);

            printf("after subtraction: ");
            for(int j = 0 ; j < 4; j++)
                 printf("%02x", temp[j]);
            printf(" ");
            printf(" rcon [i/nk]: %08x ", rCon[i/getNK(ctx->mode)]);
            temp[0] ^= rCon[i/getNK(ctx->mode)];

            printf("after xor: ");
            for(int j = 0 ; j < 4; j++)
                 printf("%02x", temp[j]);
        }
        else if(getNK(ctx->mode) > 6 && (i % getNK(ctx->mode)) == 4)
            subWord(temp);

        printf("w[i-nk]: ");
        for(int j = 0; j < 4; j++)
        {
            printf("%02x", ctx->w[ (i - getNK(ctx->mode))*4 + j ]);
            ctx->w[(i*4) + j] = ctx->w[ (i - getNK(ctx->mode))*4 + j ] ^ temp[j];
        }
        printf(" ");

        printf("xor'd: ");
        for(int j = 0; j < 4; j++)
            printf("%02x", ctx->w[(i*4) + j]);
        printf("\n");
    }
    
    return retCode;
}

int FIPS_197_5_1_4_AddRoundKey(int round, uint8_t state[4][4], const uint8_t *w)
{
    
    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            (state)[i][j] ^= w[ (round * nB * 4) + (i* nB) + j ];
            
    return 0;
}

int FIPS_197_5_1_Cipher(AES_CTX *ctx)
{
    int retcode = 0;
    printf("start state: %s\n", stateToString(ctx->state));

    FIPS_197_5_1_4_AddRoundKey(0, ctx->state, ctx->w);

    for(int round = 1; round <= getNR(ctx->mode)-1; round++)
    {
        printf("Cipher Round [ %d ]: ", round);
        printf("start rnd: %s ", stateToString(ctx->state));
        subWord(ctx->state);

        printf("after sub: %s ", stateToString(ctx->state));

        shiftRows(ctx->state);
        printf("after shift: %s ", stateToString(ctx->state));
       
        mixColumns(ctx->state);
        printf("after mix: %s", stateToString(ctx->state));

        FIPS_197_5_1_4_AddRoundKey(round, ctx->state, ctx->w);
        printf("\n");
    }
        printf("Cipher Round [ %d ]: ", getNR(ctx->mode));
        printf("start rnd: %s ", stateToString(ctx->state));
        subWord(ctx->state);
        printf("after sub: %s ", stateToString(ctx->state));
        shiftRows(ctx->state);
        printf("after shift: %s\n", stateToString(ctx->state));
        FIPS_197_5_1_4_AddRoundKey(getNR(ctx->mode), ctx->state, ctx->w);
        printf("output state: %s\n", stateToString(ctx->state));

    return retcode;
}