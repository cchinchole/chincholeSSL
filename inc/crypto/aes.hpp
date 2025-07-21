#pragma once
#include "../utils/bytes.hpp"
#include "../types.hpp"
#include <memory>


namespace cssl
{
class Aes {
    private:
        struct Impl;
        AES_MODE mode_;
        std::unique_ptr<Impl> pimpl_;
    public:
        Aes(AES_MODE mode, AES_KEYSIZE keySize);
        ~Aes();

        Aes &operator=(Aes &&other) noexcept;
        
        Aes &operator=(const Aes &other) = delete;

        void load_key(ByteSpan key, ByteSpan iv);
        void load_key(ByteSpan key);
        void load_key(std::string key, std::string iv);
        void load_key(std::string key);
        ByteArray encrypt(ByteSpan message);
        ByteArray decrypt(ByteSpan cipher);
};
}
