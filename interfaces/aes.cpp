#include "../inc/utils/bytes.hpp"
#include "../internal/aes.hpp"
#include "../inc/crypto/aes.hpp"
#include "../inc/utils/logger.hpp"

class AES::Impl
{
    public:
    AES_CTX *ctx_;
    Impl(AES_MODE mode, AES_KEYSIZE keySize)
    {
        ctx_ = new AES_CTX(mode, keySize);
    }
    ~Impl()
    {
        delete ctx_;
    }
};

ByteArray encrypt(ByteSpan message);
ByteArray decrypt(ByteSpan cipher);

AES &AES::operator=(AES &&other) noexcept
{
    if (this != &other)
    {
        delete this->pImpl;
        this->pImpl = other.pImpl;
        other.pImpl = nullptr;
        this->mode = other.mode;
    }
    return *this;
}

AES::AES(AES_MODE mode, AES_KEYSIZE keySize)
{
    this->mode = mode;
    this->pImpl = new Impl(mode, keySize);
}

void AES::addKey(ByteSpan key, ByteSpan IV)
{
    AES_KeyExpansion(*this->pImpl->ctx_, key);
    AES_SetIV(*this->pImpl->ctx_, IV);
}

void AES::addKey(ByteSpan key)
{
    if(this->mode == AES_MODE::ECB)
        AES_KeyExpansion(*this->pImpl->ctx_, key);
    else
        LOG_ERROR("Attempting to load only a key in non ECB mode");
}

void AES::addKey(std::string key, std::string IV)
{
    addKey(hexToBytes(key), hexToBytes(IV));
}

void AES::addKey(std::string key)
{
    addKey(hexToBytes(key));
}

ByteArray AES::encrypt(ByteSpan message)
{
    return AES_Encrypt(*this->pImpl->ctx_, message);
}

ByteArray AES::decrypt(ByteSpan cipher)
{
    return AES_Decrypt(*this->pImpl->ctx_, cipher);
}

AES::~AES()
{
    delete this->pImpl;
}

