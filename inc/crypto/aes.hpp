#pragma once
#include <memory>
#include "../utils/bytes.hpp"
#include "../types.hpp"

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

class AES {
    private:
        AES_MODE mode;
        class Impl;
        Impl *pImpl;
    public:
        AES(AES_MODE mode, AES_KEYSIZE keySize);
        ~AES();

        //Move operator
        AES &operator=(AES &&other) noexcept;
        
        //Delete the copy operator
        AES &operator=(const AES &other) = delete;

        void addKey(ByteSpan key, ByteSpan IV);
        void addKey(ByteSpan key);
        void addKey(std::string key, std::string IV);
        void addKey(std::string key);
        ByteArray encrypt(ByteSpan message);
        ByteArray decrypt(ByteSpan cipher);
};
