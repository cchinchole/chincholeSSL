#include "../inc/hash/hash.hpp"
#include "../internal/hmac.hpp"
#include "../internal/sha.hpp"

namespace CSSL
{
class Hasher::Impl
{
public:
    SHA_Context *ctx_;
    DIGEST_MODE mode_;
    bool finalized_;

    Impl(DIGEST_MODE mode) : mode_(mode), finalized_(false)
    {
        ctx_ = SHA_Context_new(mode);
    }

    ~Impl()
    {
        if (ctx_)
        {
            ctx_->clear();
            delete ctx_;
        }
    }

    void reset()
    {
        if (ctx_)
        {
            ctx_->clear();
        }
        else
        {
            ctx_ = SHA_Context_new(mode_);
        }
        finalized_ = false;
    }

    void update(ByteSpan data)
    {
        if (finalized_)
        {
            reset();
        }
        SHA_Update(const_cast<uint8_t *>(data.data()), data.size(), ctx_);
    }

    void update(const std::unique_ptr<uint8_t[]> &data, size_t length)
    {
        if (finalized_)
        {
            reset();
        }
        SHA_Update(data.get(), length, ctx_);
    }

    ByteArray digest()
    {
        if (finalized_)
        {
            reset();
        }
        ByteArray result(getSHAReturnLengthByMode(mode_));
        SHA_Digest(result.data(), ctx_);
        finalized_ = true;
        return result;
    }

    ByteArray xof(size_t length)
    {
        if (mode_ != DIGEST_MODE::SHA_3_SHAKE_128 &&
            mode_ != DIGEST_MODE::SHA_3_SHAKE_256)
        {
            return ByteArray(0);
        }
        if (finalized_)
        {
            reset();
        }
        ByteArray result(length);
        SHA_SHAKE_DIGEST_BYTES(ctx_, length);
        SHA_3_xof(ctx_);
        SHA_3_shake_digest(result.data(), length, ctx_);
        finalized_ = true;
        return result;
    }
};

Hasher::Hasher(DIGEST_MODE mode) : impl_(new Impl(mode)) {}

Hasher::~Hasher() { delete impl_; }

Hasher::Hasher(Hasher &&other) noexcept : impl_(other.impl_)
{
    other.impl_ = nullptr;
}

Hasher &Hasher::operator=(Hasher &&other) noexcept
{
    if (this != &other)
    {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

void Hasher::reset() { impl_->reset(); }

Hasher &Hasher::update(ByteSpan data)
{
    impl_->update(data);
    return *this;
}

Hasher &Hasher::update(const std::unique_ptr<uint8_t[]> &data, size_t length)
{
    impl_->update(data, length);
    return *this;
}

ByteArray Hasher::digest() { return impl_->digest(); }

ByteArray Hasher::xof(size_t length) { return impl_->xof(length); }

ByteArray Hasher::hash(ByteSpan data, DIGEST_MODE mode)
{
    Hasher hasher(mode);
    hasher.update(data);
    return hasher.digest();
}

ByteArray Hasher::xof(ByteSpan data, size_t BDigestLength, DIGEST_MODE mode)
{
    Hasher hasher(mode);
    hasher.update(data);
    return hasher.xof(BDigestLength);
}

ByteArray Hasher::hmac(ByteSpan data, ByteSpan key, DIGEST_MODE mode)
{
    SHA_Context *ctx = SHA_Context_new(mode);
    ByteArray result(getSHAReturnLengthByMode(mode));
    hmac_sha(ctx->mode, result.data(), data, key);
    delete ctx;
    return result;
}

size_t Hasher::returnLength()
{
    return getSHAReturnLengthByMode(impl_->ctx_->mode);
}
}
