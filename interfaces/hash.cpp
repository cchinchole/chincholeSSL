#include "../inc/hash/hash.hpp"
#include "../internal/hmac.hpp"
#include "../internal/sha.hpp"

namespace cssl
{
class Hasher::Impl
{
public:
    ShaContext *ctx_;
    DIGEST_MODE mode_;
    bool finalized_;

    Impl(DIGEST_MODE mode) : mode_(mode), finalized_(false)
    {
        ctx_ = sha_new_context(mode);
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
            ctx_ = sha_new_context(mode_);
        }
        finalized_ = false;
    }

    void update(ByteSpan data)
    {
        if (finalized_)
        {
            reset();
        }
        sha_update(const_cast<uint8_t *>(data.data()), data.size(), ctx_);
    }

    void update(const std::unique_ptr<uint8_t[]> &data, size_t length)
    {
        if (finalized_)
        {
            reset();
        }
        sha_update(data.get(), length, ctx_);
    }

    ByteArray digest()
    {
        if (finalized_)
        {
            reset();
        }
        ByteArray result(get_return_length(mode_));
        sha_digest(result.data(), ctx_);
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
        sha3_shake_digest_bytes(ctx_, length);
        sha3_xof(ctx_);
        sha3_shake_digest(result.data(), length, ctx_);
        finalized_ = true;
        return result;
    }
};

Hasher::Hasher(DIGEST_MODE mode) : pimpl_(new Impl(mode)) {}

Hasher::~Hasher() { delete pimpl_; }

Hasher::Hasher(Hasher &&other) noexcept : pimpl_(other.pimpl_)
{
    other.pimpl_ = nullptr;
}

Hasher &Hasher::operator=(Hasher &&other) noexcept
{
    if (this != &other)
    {
        delete pimpl_;
        pimpl_ = other.pimpl_;
        other.pimpl_ = nullptr;
    }
    return *this;
}

void Hasher::reset() { pimpl_->reset(); }

Hasher &Hasher::update(ByteSpan data)
{
    pimpl_->update(data);
    return *this;
}

Hasher &Hasher::update(const std::unique_ptr<uint8_t[]> &data, size_t length)
{
    pimpl_->update(data, length);
    return *this;
}

ByteArray Hasher::digest() { return pimpl_->digest(); }

ByteArray Hasher::xof(size_t length) { return pimpl_->xof(length); }

ByteArray Hasher::hash(ByteSpan data, DIGEST_MODE mode)
{
    Hasher hasher(mode);
    hasher.update(data);
    return hasher.digest();
}

ByteArray Hasher::xof(ByteSpan data, size_t digest_length_bytes, DIGEST_MODE mode)
{
    Hasher hasher(mode);
    hasher.update(data);
    return hasher.xof(digest_length_bytes);
}

ByteArray Hasher::hmac(ByteSpan data, ByteSpan key, DIGEST_MODE mode)
{
    ShaContext *ctx = sha_new_context(mode);
    ByteArray result(get_return_length(mode));
    hmacFinalize(ctx->mode_, result.data(), data, key);
    delete ctx;
    return result;
}

size_t Hasher::return_length()
{
    return get_return_length(pimpl_->ctx_->mode_);
}

size_t Hasher::block_length()
{
    return get_block_length(pimpl_->ctx_->mode_);
}
}
