#ifndef HASH_HPP
#define HASH_HPP
#include "../types.hpp"
#include "../utils/bytes.hpp"
#include <memory>
#include <span>
#include <string>
#include <vector>

class Hasher
{
private:
    class Impl;
    Impl *impl_;
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

    size_t returnLength();

    ByteArray xof(size_t length);

    static ByteArray hash(ByteSpan data, DIGEST_MODE mode);

    static ByteArray xof(ByteSpan data, size_t BDigestLength, DIGEST_MODE mode);

    static ByteArray hmac(ByteSpan data, ByteSpan key, DIGEST_MODE mode);
};
#endif
