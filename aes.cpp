#include "inc/crypto/aes.hpp"
#include <stdio.h>
#include <memory>
#include "inc/utils/bytes.hpp"
#include "malloc.h"
#include "string"
#include "cstring"
#include "inc/utils/logger.hpp"

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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/* FIPS 197 5.3.2*/
const uint8_t invsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

/* FIPS 197 5.2 - Table 5 added 0x00 as padding */
const uint8_t rCon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36};

/* FOR (nk,nr) AES256: 8,14 , 192: 6,12; 128: 4, 10*/
int getNR(AES_MODE mode)
{
    switch (mode)
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
    switch (mode)
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
    for (int i = 0; i < 3; i++)
        temp[i] = a[i + 1];
    temp[3] = a[0];

    for (int i = 0; i < 4; i++)
        a[i] = temp[i];
    return 0;
}

int SubWord(uint8_t *a)
{
    uint8_t temp[4];
    for (int i = 0; i < 4; i++)
        temp[i] = sbox[a[i]];

    for (int i = 0; i < 4; i++)
        a[i] = temp[i];
    return 0;
}

int SubWord(uint8_t state[4][4])
{

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];
    return 0;
}

int InvSubWord(uint8_t state[4][4])
{

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = invsbox[state[i][j]];
    return 0;
}

int ShiftRows(uint8_t state[4][4])
{

    uint8_t temp;
    temp = state[0][1];
    for (int i = 0; i < 3; i++)
    {
        state[i][1] = state[i + 1][1];
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

int InvShiftRows(uint8_t state[4][4])
{

    uint8_t temp;
    temp = state[3][1];
    for (int i = 3; i > 0; i--)
    {
        state[i][1] = state[i - 1][1];
    }
    state[0][1] = temp;

    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    temp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = temp;

    return 0;
}

uint8_t xtime(uint8_t x)
{
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

int MixColumns(uint8_t state[4][4])
{
    for (int i = 0; i < 4; i++)
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

uint8_t AESMult(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
            ((y >> 1 & 1) * xtime(x)) ^
            ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

int SetIV(AES_CTX *ctx, uint8_t *iv)
{
    memcpy(ctx->iv, iv, AES_BlockSize);
    return 0;
}

int InvMixColumns(uint8_t state[4][4])
{
    /* FIPS 197 5.3.3 */
    uint8_t multK[16] = {
        0x0e,
        0x0b,
        0x0d,
        0x09,
        0x09,
        0x0e,
        0x0b,
        0x0d,
        0x0d,
        0x09,
        0x0e,
        0x0b,
        0x0b,
        0x0d,
        0x09,
        0x0e,
    };
    for (int i = 0; i < 4; i++)
    {
        uint8_t tmp[4] = {state[i][0], state[i][1], state[i][2], state[i][3]};

        for (int j = 0; j < 4; j++) /* enumerating which state */
        {
            state[i][j] = 0;
            for (int k = 0; k < 4; k++) /* enumerating the variables */
                state[i][j] ^= AESMult(tmp[k], multK[j * 4 + k]);
        }
    }
    return 0;
}

char *stateToString(uint8_t state[nB][nB])
{

    char *dest = (char *)malloc(2 * AES_BlockSize + 1);
    if (!dest)
        return NULL;

    char *p = dest;
    for (size_t i = 0; i < nB; i++)
        for (size_t j = 0; j < nB; j++)
            p += sprintf((char *)p, "%02hhX", (state[j][i]));
    return dest;
}

char *roundkeyToString(const uint8_t *w)
{

    char *dest = (char *)malloc(2 * AES_BlockSize + 1);
    if (!dest)
        return NULL;

    char *p = dest;
    for (size_t i = 0; i < nB; i++)
        for (size_t j = 0; j < nB; j++)
            p += sprintf((char *)p, "%02hhX", (w[(j * nB) + i]));
    return dest;
}

int FIPS_197_5_2_KeyExpansion(AES_CTX *ctx, uint8_t *key)
{

    int retCode = 0;
    uint8_t temp[4];

    for (int i = 0; i <= getNK(ctx->mode) - 1; i++)
        for (int j = 0; j < 4; j++)
            ctx->w[(i * 4) + j] = key[(i * 4) + j];

    for (int i = 0; i <= getNK(ctx->mode) - 1; i++)
        for (int j = 0; j < 4; j++)
            _Logger->aes_printf("%02x", ctx->w[(i * 4) + j]);
    _Logger->aes_printf(" is the input to w\n");

    for (int i = getNK(ctx->mode); i <= 4 * getNR(ctx->mode) + 3; i++)
    {
        for (int j = 0; j < 4; j++)
            temp[j] = ctx->w[(i - 1) * 4 + j];

        _Logger->aes_printf("[Round %d] temp: ", i);
        for (int j = 0; j < 4; j++)
            _Logger->aes_printf("%02x", temp[j]);
        _Logger->aes_printf(" ");

        if (i % getNK(ctx->mode) == 0)
        {
            rotateWord(temp);

            _Logger->aes_printf("after rotate: ");
            for (int j = 0; j < 4; j++)
                _Logger->aes_printf("%02x", temp[j]);
            _Logger->aes_printf(" ");

            SubWord(temp);

            _Logger->aes_printf("after subtraction: ");
            for (int j = 0; j < 4; j++)
                _Logger->aes_printf("%02x", temp[j]);
            _Logger->aes_printf(" ");
            _Logger->aes_printf(" rcon [i/nk]: %08x ", rCon[i / getNK(ctx->mode)]);
            temp[0] ^= rCon[i / getNK(ctx->mode)];

            _Logger->aes_printf("after xor: ");
            for (int j = 0; j < 4; j++)
                _Logger->aes_printf("%02x", temp[j]);
        }
        else if (getNK(ctx->mode) > 6 && (i % getNK(ctx->mode)) == 4)
            SubWord(temp);

        _Logger->aes_printf("w[i-nk]: ");
        for (int j = 0; j < 4; j++)
        {
            _Logger->aes_printf("%02x", ctx->w[(i - getNK(ctx->mode)) * 4 + j]);
            ctx->w[(i * 4) + j] = ctx->w[(i - getNK(ctx->mode)) * 4 + j] ^ temp[j];
        }
        _Logger->aes_printf(" ");

        _Logger->aes_printf("xor'd: ");
        for (int j = 0; j < 4; j++)
            _Logger->aes_printf("%02x", ctx->w[(i * 4) + j]);
        _Logger->aes_printf("\n");
    }

    return retCode;
}

int FIPS_197_5_1_4_AddRoundKey(int round, uint8_t state[4][4], const uint8_t *w)
{

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            (state)[i][j] ^= w[(round * nB * 4) + (i * nB) + j];

    return 0;
}

int FIPS_197_5_1_Cipher(AES_CTX *ctx)
{
    int retcode = 0;
    //    _Logger->aes_printf("start state: %s\n", stateToString(ctx->state));

    FIPS_197_5_1_4_AddRoundKey(0, ctx->state, ctx->w);

    for (int round = 1; round <= getNR(ctx->mode) - 1; round++)
    {
        //      _Logger->aes_printf("Cipher Round [ %d ]: ", round);
        //     _Logger->aes_printf("start rnd: %s ", stateToString(ctx->state));
        SubWord(ctx->state);

        //        _Logger->aes_printf("after sub: %s ", stateToString(ctx->state));

        ShiftRows(ctx->state);
        //      _Logger->aes_printf("after shift: %s ", stateToString(ctx->state));

        MixColumns(ctx->state);
        //    _Logger->aes_printf("after mix: %s", stateToString(ctx->state));

        FIPS_197_5_1_4_AddRoundKey(round, ctx->state, ctx->w);
        //  _Logger->aes_printf("\n");
    }
    //_Logger->aes_printf("Cipher Round [ %d ]: ", getNR(ctx->mode));
    //_Logger->aes_printf("start rnd: %s ", stateToString(ctx->state));
    SubWord(ctx->state);
    //_Logger->aes_printf("after sub: %s ", stateToString(ctx->state));
    ShiftRows(ctx->state);
    //_Logger->aes_printf("after shift: %s\n", stateToString(ctx->state));
    FIPS_197_5_1_4_AddRoundKey(getNR(ctx->mode), ctx->state, ctx->w);
    //_Logger->aes_printf("output state: %s\n", stateToString(ctx->state));

    return retcode;
}

int FIPS_197_5_3_InvCipher(AES_CTX *ctx)
{
    int retcode = 0;
    _Logger->aes_printf("start state: %s\n", stateToString(ctx->state));

    FIPS_197_5_1_4_AddRoundKey(getNR(ctx->mode), ctx->state, ctx->w);

    for (int round = getNR(ctx->mode) - 1; round >= 1; round--)
    {
        _Logger->aes_printf("InvCipher Round [ %d ]: ", round);

        _Logger->aes_printf("start rnd: %s ", stateToString(ctx->state));

        InvShiftRows(ctx->state);
        _Logger->aes_printf("after invshift: %s ", stateToString(ctx->state));

        InvSubWord(ctx->state);
        _Logger->aes_printf("after invsub: %s ", stateToString(ctx->state));

        FIPS_197_5_1_4_AddRoundKey(round, ctx->state, ctx->w);

        InvMixColumns(ctx->state);
        _Logger->aes_printf("after invmix: %s", stateToString(ctx->state));

        _Logger->aes_printf("\n");
    }
    _Logger->aes_printf("Cipher Round [ %d ]: ", 0);
    _Logger->aes_printf("start rnd: %s ", stateToString(ctx->state));
    InvShiftRows(ctx->state);
    _Logger->aes_printf("after invshift: %s", stateToString(ctx->state));

    InvSubWord(ctx->state);
    _Logger->aes_printf("after invsub: %s ", stateToString(ctx->state));

    FIPS_197_5_1_4_AddRoundKey(0, ctx->state, ctx->w);
    _Logger->aes_printf("output state: %s\n", stateToString(ctx->state));

    return retcode;
}

// SP800-38A  6.2
int CBC_Encrypt(AES_CTX *ctx, uint8_t *output, uint8_t *buf, size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx->iv, 16);
    for (int i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(ctx->state, buf, AES_BlockSize);

        /* XOR'ing the current buffer segment with the IV */
        for (int j = 0; j < 4; j++)
            for (int k = 0; k < 4; k++)
                ctx->state[j][k] ^= iv[j * 4 + k];

        FIPS_197_5_1_Cipher(ctx);
        memcpy(output, ctx->state, AES_BlockSize);
        memcpy(iv, ctx->state, AES_BlockSize);
        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

// SP800-38A 6.2
int CBC_Decrypt(AES_CTX *ctx, uint8_t *output, uint8_t *buf, size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx->iv, 16);
    uint8_t nextIV[AES_BlockSize];
    for (int i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(nextIV, buf, AES_BlockSize);
        memcpy(ctx->state, buf, AES_BlockSize);
        FIPS_197_5_3_InvCipher(ctx);

        /* XOR'ing the current buffer segment with the IV */
        for (int j = 0; j < 4; j++)
            for (int k = 0; k < 4; k++)
                ctx->state[j][k] ^= iv[j * 4 + k];

        memcpy(output, ctx->state, AES_BlockSize);
        memcpy(iv, nextIV, AES_BlockSize);
        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

/* Uses the IV as the Tcounter, properly set the IV using the standard counter method */
// SP800-38A 6.5
int CTR_xcrypt(AES_CTX *ctx, uint8_t *out, uint8_t *buf, size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx->iv, 16);
    uint8_t TCounterBuffer[AES_BlockSize];
    for (int j = 0, TInc = AES_BlockSize; j < buf_len; j++, TInc++)
    {
        if (TInc == AES_BlockSize)
        {
            memcpy(TCounterBuffer, iv, AES_BlockSize);
            memcpy(ctx->state, TCounterBuffer, AES_BlockSize);
            FIPS_197_5_1_Cipher(ctx);
            memcpy(TCounterBuffer, ctx->state, AES_BlockSize);

            for (int i = AES_BlockSize - 1; i >= 0; i--)
                if (iv[i] == 0xFF)
                    iv[i] = 0;
                else
                {
                    iv[i]++;
                    break;
                }
            TInc = 0;
        }
        out[j] = buf[j] ^ TCounterBuffer[TInc];
    }
    return 0;
}