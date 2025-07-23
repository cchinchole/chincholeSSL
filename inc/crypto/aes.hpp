#pragma once
#include "../types.hpp"
#include "../utils/bytes.hpp"
#include <memory>

namespace cssl {
class Aes {
private:
    struct Impl;
    AES_MODE mode_;
    std::unique_ptr<Impl> pimpl_;

public:
    explicit Aes(AES_MODE mode, AES_KEYSIZE keySize);
    ~Aes();
    Aes &operator=(Aes &&other) noexcept;
    Aes &operator=(const Aes &other) = delete;

    bool load_key(ByteSpan key, ByteSpan iv);
    bool load_key(ByteSpan key);
    bool load_key(std::string key, std::string iv);
    bool load_key(std::string key);
    ByteArray encrypt(ByteSpan message);
    ByteArray decrypt(ByteSpan cipher);
};
}
