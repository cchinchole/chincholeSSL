#include "internal/aes.hpp"

#include <stdio.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "cstring"
#include "inc/utils/logger.hpp"

/* FIPS 197 5.1.1 table 4 */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

/* FIPS 197 5.3.2*/
static const uint8_t invSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

/* FIPS 197 5.2 - Table 5 added 0x00 as padding */
const uint8_t rCon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                          0x20, 0x40, 0x80, 0x1b, 0x36};

static constexpr std::array<int, 3> tNR = {10, 12, 14};
static constexpr std::array<int, 3> tNK = {4, 6, 8};

/* FOR (nk,nr) AES256: 8,14 , 192: 6,12; 128: 4, 10*/
int getNR(AesContext &ctx) { return tNR[static_cast<int>(ctx.key_size_)]; }

int getNK(AesContext &ctx) { return tNK[static_cast<int>(ctx.key_size_)]; }

std::string roundKeyToString(const uint8_t *w)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t i = 0; i < nB; i++)
        for (uint8_t j = 0; j < nB; j++)
            oss << std::setw(2) << static_cast<unsigned>(w[(j * nB) + i]);

    return oss.str();
}

std::string tempToString(const uint8_t *temp)
{
    std::stringstream ss;
    for (uint8_t j = 0; j < nB; j++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(temp[j]);
        if (j < 3)
            ss << " ";
    }
    return ss.str();
}

std::string wnkToString(AesContext &ctx, uint8_t i)
{
    std::stringstream ss;
    for (uint8_t j = 0; j < nB; j++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(ctx.w_[(i - getNK(ctx)) * 4 + j]);
        if (j < 3)
            ss << " ";
    }
    return ss.str();
}

std::string wnkOpsToString(AesContext &ctx, uint8_t i)
{
    std::stringstream ss;
    for (uint8_t j = 0; j < nB; j++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(ctx.w_[(i) * 4 + j]);
        if (j < 3)
            ss << " ";
    }
    return ss.str();
}

std::string stateToString(uint8_t state[nB][nB])
{
    std::string result;
    result.reserve(2 * nB * nB + 1);
    char buf[3];
    for (uint8_t i = 0; i < nB; i++)
    {
        for (uint8_t j = 0; j < nB; j++)
        {
            snprintf(buf, 3, "%02hhX", state[j][i]);
            result += buf;
        }
    }
    return result;
}

void rotateWord(uint8_t *a)
{
    uint8_t temp[4];
    for (uint8_t i = 0; i < 3; i++)
        temp[i] = a[i + 1];
    temp[3] = a[0];

    for (uint8_t i = 0; i < 4; i++)
        a[i] = temp[i];
}

void subWord(uint8_t *a)
{
    uint8_t temp[4];
    for (uint8_t i = 0; i < 4; i++)
        temp[i] = sbox[a[i]];

    for (uint8_t i = 0; i < 4; i++)
        a[i] = temp[i];
}

void subWord(uint8_t state[4][4])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];
}

void invSubWord(uint8_t state[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
        for (uint8_t j = 0; j < 4; j++)
            state[i][j] = invSBox[state[i][j]];
}

void shiftRows(uint8_t state[4][4])
{
    uint8_t temp;
    temp = state[0][1];
    for (uint8_t i = 0; i < nB - 1; i++)
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
}

void invShiftRows(uint8_t state[4][4])
{
    uint8_t temp;
    temp = state[3][1];
    for (uint8_t i = nB - 1; i > 0; i--)
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
}

uint8_t xTime(uint8_t x) { return (x << 1) ^ (((x >> 7) & 1) * 0x1b); }

void mixColumns(uint8_t state[nB][nB])
{
    for (uint8_t i = 0; i < nB; i++)
    {
        uint8_t tmp = state[i][0];
        uint8_t tmp2 = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];

        uint8_t tmp3 = state[i][0] ^ state[i][1];
        tmp3 = xTime(tmp3);
        state[i][0] ^= tmp3 ^ tmp2;

        tmp3 = state[i][1] ^ state[i][2];
        tmp3 = xTime(tmp3);
        state[i][1] ^= tmp3 ^ tmp2;

        tmp3 = state[i][2] ^ state[i][3];
        tmp3 = xTime(tmp3);
        state[i][2] ^= tmp3 ^ tmp2;

        tmp3 = state[i][3] ^ tmp;
        tmp3 = xTime(tmp3);
        state[i][3] ^= tmp3 ^ tmp2;
    }
}

uint8_t aMult(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^ ((y >> 1 & 1) * xTime(x)) ^
            ((y >> 2 & 1) * xTime(xTime(x))) ^
            ((y >> 3 & 1) * xTime(xTime(xTime(x)))) ^
            ((y >> 4 & 1) * xTime(xTime(xTime(xTime(x))))));
}

/* FIPS 197 5.3.3 */
void invMixColumns(uint8_t state[4][4])
{
    uint8_t multK[16] = {
        0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e,
    };
    for (uint8_t i = 0; i < 4; i++)
    {
        uint8_t tmp[4] = {state[i][0], state[i][1], state[i][2], state[i][3]};
        for (uint8_t j = 0; j < nB; j++) // enumerating which state
        {
            state[i][j] = 0;
            for (uint8_t k = 0; k < nB; k++) // enumerating the variables
                state[i][j] ^= aMult(tmp[k], multK[j * 4 + k]);
        }
    }
}

// TODO Fix the debugging in this.
// FIPS_197_5_2
int keyExpansion(AesContext &ctx, const uint8_t *key)
{
    int retCode = 0;
    uint8_t temp[4];
    for (uint8_t i = 0; i <= getNK(ctx) - 1; i++)
        for (uint8_t j = 0; j < nB; j++)
            ctx.w_[(i * nB) + j] = key[(i * nB) + j];

    LOG_AES("[Key Expansion (w)]: {}\n", roundKeyToString(ctx.w_));
    for (uint8_t i = getNK(ctx); i <= 4 * getNR(ctx) + 3; i++)
    {
        for (uint8_t j = 0; j < nB; j++)
            temp[j] = ctx.w_[(i - 1) * nB + j];
        LOG_AES("[KeyExpansion Round {}]", i);
        LOG_AES("temp: {}", tempToString(temp));
        if (i % getNK(ctx) == 0)
        {
            rotateWord(temp);
            LOG_AES("after rotate temp: {}", tempToString(temp));

            subWord(temp);
            LOG_AES("after subtract temp: {}", tempToString(temp));

            temp[0] ^= rCon[i / getNK(ctx)];
            LOG_AES("after xor temp: {}", tempToString(temp));
        }
        else if (getNK(ctx) > 6 && (i % getNK(ctx)) == 4)
        {
            subWord(temp);
            LOG_AES("after subtract temp: {}", tempToString(temp));
        }

        LOG_AES("w[i-nk]: {}", wnkToString(ctx, i));
        for (uint8_t j = 0; j < nB; j++)
        {
            ctx.w_[(i * nB) + j] = ctx.w_[(i - getNK(ctx)) * nB + j] ^ temp[j];
        }
        LOG_AES("w[i] xor: {}\n", wnkOpsToString(ctx, i));
    }
    return retCode;
}

//FIPS_197_5_1_4
void addRoundKey(int round, uint8_t state[nB][nB],
                               const uint8_t *w)
{
    for (uint8_t i = 0; i < nB; i++)
        for (uint8_t j = 0; j < nB; j++)
            (state)[i][j] ^= w[(round * nB * nB) + (i * nB) + j];
}

//FIPS_197_5_1
int aCipher(AesContext &ctx)
{
    int retcode = 0;
    LOG_AES("start state: {}\n", stateToString(ctx.state_).c_str());

    addRoundKey(0, ctx.state_, ctx.w_);

    for (uint8_t round = 1; round <= getNR(ctx) - 1; round++)
    {
        LOG_AES("Cipher Round [ {} ]:", round);

        LOG_AES("start rnd: {} ", stateToString(ctx.state_).c_str());
        subWord(ctx.state_);

        LOG_AES("after sub: {} ", stateToString(ctx.state_).c_str());
        shiftRows(ctx.state_);

        LOG_AES("after shift: {} ", stateToString(ctx.state_).c_str());
        mixColumns(ctx.state_);

        LOG_AES("after mix: {}\n", stateToString(ctx.state_).c_str());
        addRoundKey(round, ctx.state_, ctx.w_);
    }

    LOG_AES("Cipher Round [ {} ]: ", getNR(ctx));
    LOG_AES("start rnd: {}", stateToString(ctx.state_).c_str());

    subWord(ctx.state_);
    LOG_AES("after sub: {}", stateToString(ctx.state_).c_str());

    shiftRows(ctx.state_);
    LOG_AES("after shift: {}", stateToString(ctx.state_).c_str());

    addRoundKey(getNR(ctx), ctx.state_, ctx.w_);
    LOG_AES("output state: {}\n", stateToString(ctx.state_).c_str());
    return retcode;
}

//FIPS_197_5_3_
int invCipher(AesContext &ctx)
{
    int retcode = 0;
    LOG_AES("start state: {}\n", stateToString(ctx.state_).c_str());

    addRoundKey(getNR(ctx), ctx.state_, ctx.w_);
    for (uint8_t round = getNR(ctx) - 1; round >= 1; round--)
    {
        LOG_AES("InvCipher Round [ {} ]: ", round);
        LOG_AES("start rnd: {}", stateToString(ctx.state_).c_str());
        invShiftRows(ctx.state_);

        LOG_AES("after invshift: {}", stateToString(ctx.state_).c_str());
        invSubWord(ctx.state_);

        LOG_AES("after invsub: {}", stateToString(ctx.state_).c_str());
        addRoundKey(round, ctx.state_, ctx.w_);

        invMixColumns(ctx.state_);
        LOG_AES("after invmix: {}\n", stateToString(ctx.state_).c_str());
    }
    LOG_AES("Cipher Round [ {} ]: ", 0);
    LOG_AES("start rnd: {}", stateToString(ctx.state_).c_str());
    invShiftRows(ctx.state_);

    LOG_AES("after invshift: {}", stateToString(ctx.state_).c_str());
    invSubWord(ctx.state_);

    LOG_AES("after invsub: {}", stateToString(ctx.state_).c_str());
    addRoundKey(0, ctx.state_, ctx.w_);

    LOG_AES("output state: {}\n", stateToString(ctx.state_).c_str());
    return retcode;
}

// SP800-38A  6.1
int ecbEncrypt(AesContext &ctx, uint8_t *output, const uint8_t *buf,
                size_t buf_len)
{
    for (size_t i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(ctx.state_, buf, AES_BlockSize);
        aCipher(ctx);
        memcpy(output, ctx.state_, AES_BlockSize);
        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

// SP800-38A  6.1
int ecbDecrypt(AesContext &ctx, uint8_t *output, const uint8_t *buf,
                size_t buf_len)
{
    for (size_t i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(ctx.state_, buf, AES_BlockSize);
        invCipher(ctx);
        memcpy(output, ctx.state_, AES_BlockSize);
        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

// SP800-38A  6.2
int cbcEncrypt(AesContext &ctx, uint8_t *output, const uint8_t *buf,
                size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx.iv_, 16);
    for (size_t i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(ctx.state_, buf, AES_BlockSize);

        /* XOR'ing the current buffer segment with the IV */
        for (size_t j = 0; j < 4; j++)
            for (size_t k = 0; k < 4; k++)
                ctx.state_[j][k] ^= iv[j * 4 + k];

        aCipher(ctx);
        memcpy(output, ctx.state_, AES_BlockSize);
        memcpy(iv, ctx.state_, AES_BlockSize);
        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

// SP800-38A 6.2
int cbcDecrypt(AesContext &ctx, uint8_t *output, const uint8_t *buf,
                size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx.iv_, 16);
    uint8_t nextIV[AES_BlockSize];
    for (size_t i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(nextIV, buf, AES_BlockSize);
        memcpy(ctx.state_, buf, AES_BlockSize);
        invCipher(ctx);

        /* XOR'ing the current buffer segment with the IV */
        for (uint8_t j = 0; j < nB; j++)
            for (uint8_t k = 0; k < nB; k++)
                ctx.state_[j][k] ^= iv[j * nB + k];

        memcpy(output, ctx.state_, AES_BlockSize);
        memcpy(iv, nextIV, AES_BlockSize);
        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

// SP800-38A 6.3
// Current implementation only works for 128mode.
int cfbXCrypt(AesContext &ctx, uint8_t *output, const uint8_t *buf,
               size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx.iv_, 16);
    uint8_t keystream[AES_BlockSize];
    for (size_t i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(ctx.state_, iv, AES_BlockSize);
        aCipher(ctx);
        memcpy(keystream, ctx.state_, AES_BlockSize);

        // XOR'ing the current buffer segment with the IV
        for (uint8_t j = 0; j < nB; j++)
            for (uint8_t k = 0; k < nB; k++)
                output[j * nB + k] = buf[j * nB + k] ^ keystream[j * nB + k];

        memcpy(iv, keystream, AES_BlockSize);

        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

// SP800-38A 6.4
int ofbXCrypt(AesContext &ctx, uint8_t *output, const uint8_t *buf,
               size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx.iv_, 16);

    uint8_t keystream[AES_BlockSize];
    for (size_t i = 0; i < buf_len; i += AES_BlockSize)
    {
        memcpy(ctx.state_, iv, AES_BlockSize);
        aCipher(ctx);
        memcpy(keystream, ctx.state_, AES_BlockSize);
        memcpy(iv, keystream, AES_BlockSize);

        // XOR'ing the current buffer segment with the IV
        for (uint8_t j = 0; j < nB; j++)
            for (uint8_t k = 0; k < nB; k++)
                output[j * nB + k] = buf[j * nB + k] ^ keystream[j * nB + k];
        buf += AES_BlockSize;
        output += AES_BlockSize;
    }
    return 0;
}

/* Uses the IV as the Tcounter, properly set the IV using the standard counter
 * method */
// SP800-38A 6.5
int ctrXCrypt(AesContext &ctx, uint8_t *out, const uint8_t *buf, size_t buf_len)
{
    uint8_t iv[16];
    memcpy(iv, ctx.iv_, 16);
    uint8_t TCounterBuffer[AES_BlockSize];
    for (size_t j = 0, TInc = AES_BlockSize; j < buf_len; j++, TInc++)
    {
        if (TInc == AES_BlockSize)
        {
            memcpy(TCounterBuffer, iv, AES_BlockSize);
            memcpy(ctx.state_, TCounterBuffer, AES_BlockSize);
            aCipher(ctx);
            memcpy(TCounterBuffer, ctx.state_, AES_BlockSize);

            for (size_t i = AES_BlockSize - 1; i >= 0; i--)
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

int aes_set_iv(AesContext &ctx, ByteSpan iv)
{
    memcpy(ctx.iv_, iv.data(), AES_BlockSize);
    return 0;
}

// Wrapped for better naming
int aes_key_expansion(AesContext &ctx, ByteSpan key)
{
    return keyExpansion(ctx, key.data());
}

ByteArray aes_encrypt(AesContext &ctx, ByteSpan buf)
{
    ByteArray output;
    output.resize(buf.size());
    switch (ctx.mode_)
    {
    case cssl::AES_MODE::CBC:
        cbcEncrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::ECB:
        ecbEncrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::CTR:
        ctrXCrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::OFB:
        ofbXCrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::CFB:
        cfbXCrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    default:
        LOG_ERROR("{} Invalid AES mode reached.", __func__);
        return ByteArray();
        break;
    }
    return output;
}

ByteArray aes_decrypt(AesContext &ctx, ByteSpan buf)
{
    ByteArray output;
    output.resize(buf.size());
    switch (ctx.mode_)
    {
    case cssl::AES_MODE::CBC:
        cbcDecrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::ECB:
        ecbDecrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::CTR:
        ctrXCrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::OFB:
        ofbXCrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    case cssl::AES_MODE::CFB:
        cfbXCrypt(ctx, output.data(), buf.data(), buf.size());
        break;

    default:
        LOG_ERROR("{} Invalid AES mode reached.", __func__);
        return ByteArray();
        break;
    }
    return output;
}
