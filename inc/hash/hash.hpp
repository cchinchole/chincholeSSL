#ifndef HASH_HPP
#define HASH_HPP
#include "../utils/bytes.hpp"
#include "../types.hpp"
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

    Hasher& update(const ByteArray& data);

    ByteArray digest();

    ByteArray xof(size_t length);

    static ByteArray hash(const ByteArray& data, DIGEST_MODE mode);

    static ByteArray xof(const ByteArray& data, size_t BDigestLength, DIGEST_MODE mode);

    static ByteArray hmac(const ByteArray& data, const ByteArray& key, DIGEST_MODE mode);

    static int getReturnLength(DIGEST_MODE mode);
};
#endif
