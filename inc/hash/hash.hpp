#pragma once
#include "../types.hpp"
#include "../utils/bytes.hpp"
#include <memory>

namespace cssl
{

class Hasher
{
private:
    class Impl;
    Impl *pimpl_;

public:
    explicit Hasher(DIGEST_MODE mode = DIGEST_MODE::SHA_1);

    ~Hasher();

    Hasher(const Hasher &) = delete;
    Hasher &operator=(const Hasher &) = delete;
    Hasher(Hasher &&) noexcept;
    Hasher &operator=(Hasher &&) noexcept;

    void reset();

    Hasher &update(ByteSpan data);
    Hasher &update(const std::unique_ptr<uint8_t[]> &data, size_t length);

    ByteArray digest();

    size_t return_length();
    size_t block_length();

    ByteArray xof(size_t length);

    static ByteArray hash(ByteSpan data, DIGEST_MODE mode);

    static ByteArray xof(ByteSpan data, size_t digest_length_bytes, DIGEST_MODE mode);

    static ByteArray hmac(ByteSpan data, ByteSpan key, DIGEST_MODE mode);
};
}
