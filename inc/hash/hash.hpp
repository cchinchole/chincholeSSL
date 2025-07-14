#ifndef HASH_HPP
#define HASH_HPP
#include "../utils/bytes.hpp"
#include "../types.hpp"
#include <span>
#include <memory>
#include <string>
#include <vector>

class Hasher {
private:
    class Impl;
    Impl* impl_;

public:
    explicit Hasher(DIGEST_MODE mode = DIGEST_MODE::SHA_1);

    ~Hasher();

    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;
    Hasher(Hasher&&) noexcept;
    Hasher& operator=(Hasher&&) noexcept;

    void reset();

    Hasher& update(std::span<const uint8_t> data);
    Hasher& update(std::unique_ptr<uint8_t[]>&& data, size_t length);

    ByteArray digest();

    size_t returnLength();

    ByteArray xof(size_t length);

    static ByteArray hash(std::span<const uint8_t> data, DIGEST_MODE mode);

    static ByteArray xof(std::span<const uint8_t> data, size_t BDigestLength, DIGEST_MODE mode);

    static ByteArray hmac(std::span<const uint8_t> data, std::span<const uint8_t> key, DIGEST_MODE mode);
};
#endif
