#pragma once
namespace cssl {
enum class DIGEST_MODE
{
    SHA_1,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_3_224,
    SHA_3_256,
    SHA_3_384,
    SHA_3_512,
    SHA_3_SHAKE_128,
    SHA_3_SHAKE_256,
    NONE
};

enum class AES_MODE
{
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    NONE
};

enum class AES_KEYSIZE
{
    m128 = 0,
    m192 = 1,
    m256 = 2
};

enum class EC_GROUP
{
    P224,
    P256,
    P384,
    P521,
    NONE
};
}
