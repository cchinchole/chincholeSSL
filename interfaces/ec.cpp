#include "../inc/crypto/ec.hpp"
#include "../internal/ec.hpp"
#include <memory>
#include <openssl/bn.h>

namespace cSSL
{
struct ECSignature::Impl {
    cECSignature sig;
};

ECSignature::~ECSignature() = default;
ECSignature::ECSignature() : pImpl(std::make_unique<Impl>()) {}
ECSignature ECSignature::From(const std::string& hexR, const std::string& hexS)
{
    ECSignature sig;
    BN_hex2bn(&sig.pImpl->sig.R, hexR.c_str());
    BN_hex2bn(&sig.pImpl->sig.S, hexS.c_str());
    return sig;
}
std::pair<std::string, std::string> ECSignature::getPairRS()
{
    char *r = BN_bn2hex(this->pImpl->sig.R);
    char *s = BN_bn2hex(this->pImpl->sig.S);
    std::string R(r);
    std::string S(s);
    OPENSSL_free(r);
    OPENSSL_free(s);
    return std::pair(R, S);
}

struct ECKeyPair::Impl {
    cECKey key;
    Impl(ECGroup group) : key(group) {} //Generate the group
};

ECKeyPair::~ECKeyPair() = default;
ECKeyPair::ECKeyPair(ECGroup group) : pImpl(std::make_unique<Impl>(group)){};

ECKeyPair ECKeyPair::Generate(ECGroup group)
{
    ECKeyPair keyPair(group);
    EC_GenerateKeyPair(keyPair.pImpl->key);
    return keyPair;
}

ECKeyPair ECKeyPair::From(ECGroup group, const std::string &hexPriv, const std::string &hexPubX, const std::string &hexPubY)
{
    ECKeyPair keyPair(group);
    BN_hex2bn(&keyPair.pImpl->key.priv, hexPriv.c_str());
    BN_hex2bn(&keyPair.pImpl->key.pub.x, hexPubX.c_str());
    BN_hex2bn(&keyPair.pImpl->key.pub.y, hexPubY.c_str());
    return keyPair;
}

ECSignature ECKeyPair::sign(std::span<const uint8_t> message,
                     DIGEST_MODE shaMode) const
{
    ECSignature sig;
    EC_GenerateSignature(this->pImpl->key, sig.pImpl->sig, message, shaMode);
    return sig;
}

bool ECKeyPair::verify(const ECSignature &sig, std::span<const uint8_t> message,
                DIGEST_MODE shaMode) const
{
    return EC_VerifySignature(this->pImpl->key, sig.pImpl->sig, message, shaMode) == 0;
}
}
