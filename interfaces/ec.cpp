#include "../inc/crypto/ec.hpp"
#include "../internal/ec.hpp"
#include <memory>
#include <openssl/bn.h>

namespace cssl
{
struct EcSignature::Impl
{
    cEcSignature sig;
};

// Signature
EcSignature::~EcSignature() = default;
EcSignature::EcSignature() : pimpl_(std::make_unique<Impl>()) {}
EcSignature EcSignature::from(const std::string &hexR, const std::string &hexS)
{
    EcSignature signature;
    BN_hex2bn(&signature.pimpl_->sig.r_, hexR.c_str());
    BN_hex2bn(&signature.pimpl_->sig.s_, hexS.c_str());
    return signature;
}
std::pair<std::string, std::string> EcSignature::get_rs()
{
    char *r = BN_bn2hex(pimpl_->sig.r_);
    char *s = BN_bn2hex(pimpl_->sig.s_);
    std::string r_str(r);
    std::string s_str(s);
    OPENSSL_free(r);
    OPENSSL_free(s);
    return std::pair(r_str, s_str);
}

// ECKeyPair
struct Ec::Impl
{
    EcKey key;
    Impl(EC_GROUP group) : key(group) {}
};

Ec::~Ec() = default;
Ec::Ec(EC_GROUP group) : m_pImpl(std::make_unique<Impl>(group)) {};

Ec Ec::generate_key(EC_GROUP group)
{
    Ec keyPair(group);
    ec_generate_keypair(keyPair.m_pImpl->key);
    return keyPair;
}

Ec Ec::from(EC_GROUP group, const std::string &hexPriv,
                          const std::string &hexPubX,
                          const std::string &hexPubY)
{
    Ec keyPair(group);
    BN_hex2bn(&keyPair.m_pImpl->key.priv_, hexPriv.c_str());
    BN_hex2bn(&keyPair.m_pImpl->key.pub_.x_, hexPubX.c_str());
    BN_hex2bn(&keyPair.m_pImpl->key.pub_.y_, hexPubY.c_str());
    return keyPair;
}

EcSignature Ec::sign(ByteSpan message, DIGEST_MODE shaMode) const
{
    EcSignature sig;
    ec_generate_signature(m_pImpl->key, sig.pimpl_->sig, message, shaMode);
    return sig;
}

bool Ec::verify(const EcSignature &sig, ByteSpan message,
                       DIGEST_MODE shaMode) const
{
    return ec_verify_signature(m_pImpl->key, sig.pimpl_->sig, message,
                              shaMode) == 0;
}
}
