#include "../inc/utils/bytes.hpp"
#include "../internal/aes.hpp"
#include "../inc/crypto/aes.hpp"
#include "../inc/utils/logger.hpp"
#include <memory>

namespace cssl
{

struct Aes::Impl
{
    AesContext ctx;
};

Aes &Aes::operator=(Aes &&other) noexcept
{
    if (this != &other)
    {
        this->pimpl_ = std::move(other.pimpl_);
        this->mode_ = other.mode_;
    }
    return *this;
}

Aes::~Aes() = default;
Aes::Aes(AES_MODE mode, AES_KEYSIZE key_size) : mode_(mode), pimpl_(std::make_unique<Impl>())
{
    this->pimpl_->ctx.mode_ = mode;
    this->pimpl_->ctx.key_size_ = key_size;
}

bool Aes::load_key(ByteSpan key, ByteSpan iv)
{
    aes_key_expansion(this->pimpl_->ctx, key);
    aes_set_iv(this->pimpl_->ctx, iv);
    return true;
}

bool Aes::load_key(ByteSpan key)
{
    if(this->mode_ == AES_MODE::ECB)
    {
        aes_key_expansion(this->pimpl_->ctx, key);
        return true;
    }
    else
    {
        LOG_ERROR("Attempting to load only a key in non ECB mode");
        return false;
    }
}

bool Aes::load_key(std::string key, std::string iv)
{
    load_key(hex_to_bytes(key), hex_to_bytes(iv));
    return true;
}

bool Aes::load_key(std::string key)
{
    if(this->mode_ == AES_MODE::ECB)
    {
        load_key(hex_to_bytes(key));
        return true;
    }
    else
    {
        LOG_ERROR("Attempting to load only a key in non ECB mode");
        return false;
    }
}

ByteArray Aes::encrypt(ByteSpan message)
{
    return aes_encrypt(this->pimpl_->ctx, message);
}

ByteArray Aes::decrypt(ByteSpan cipher)
{
    return aes_decrypt(this->pimpl_->ctx, cipher);
}
}
