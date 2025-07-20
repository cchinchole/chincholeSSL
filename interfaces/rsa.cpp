#include "../inc/crypto/rsa.hpp"
#include "../internal/rsa.hpp"
#include "../inc/utils/logger.hpp"
#include <openssl/bn.h>


namespace CSSL {
        
    void BN_strtobn(BIGNUM *bn, std::string &str)
    {
        BIGNUM *bnVal = BN_new();
        BN_hex2bn(&bnVal, str.c_str());
        BN_copy(bn, bnVal);
        BN_free(bnVal);
    }
    class RSA::Impl_ {
        public:
            cRSAKey key;
    };

    RSA::RSA(size_t bits)
    {
        this->pImpl_ = new Impl_();
        this->pImpl_->key.kBits = bits;
    }

    RSA::~RSA()
    {
        delete this->pImpl_;
    }

    bool RSA::isCRTEnabled()
    {
        return this->pImpl_->key.crt.enabled;
    }

    void RSA::fromPrimes(std::string hexP, std::string hexQ, std::string hexE)
    {
        BN_strtobn(this->pImpl_->key.crt.p, hexP);
        BN_strtobn(this->pImpl_->key.crt.q, hexQ);
        BN_strtobn(this->pImpl_->key.e, hexE);
        gen_rsa_sp800_56b(this->pImpl_->key, true);
    }
    
    void RSA::loadPublicKey(std::string hexModulus, std::string hexPublicExponent)
    {
        BN_strtobn(this->pImpl_->key.n, hexModulus);
        BN_strtobn(this->pImpl_->key.e, hexPublicExponent);
    }
    void RSA::loadPrivateKey(std::string hexModulus, std::string hexPrivateExponent)
    {
        BN_strtobn(this->pImpl_->key.n, hexModulus);
        BN_strtobn(this->pImpl_->key.d, hexPrivateExponent);
    }
    void RSA::loadCRT(std::string hexP, std::string hexQ, std::string hexDP, std::string hexDQ, std::string hexQinv)
    {
        BN_strtobn(this->pImpl_->key.crt.p, hexP);
        BN_strtobn(this->pImpl_->key.crt.q, hexQ);
        BN_strtobn(this->pImpl_->key.crt.dp, hexDP);
        BN_strtobn(this->pImpl_->key.crt.dq, hexDQ);
        BN_strtobn(this->pImpl_->key.crt.qInv, hexQinv);
        this->pImpl_->key.crt.enabled = true;
    }
    
    void RSA::generateKey()
    {
        RSA_GenerateKey(this->pImpl_->key, this->pImpl_->key.kBits);
    }

    void RSA::clearPadding()
    {
        this->pImpl_->key.reset();
    }

    void RSA::addOAEP(ByteSpan label, DIGEST_MODE labelHashMode, DIGEST_MODE mgf1HashMode)
    {
        RSA_AddOAEP(this->pImpl_->key, label, labelHashMode, mgf1HashMode);
    }

    void RSA::addOAEP(ByteSpan label, ByteSpan seed, DIGEST_MODE labelHashMode, DIGEST_MODE mgf1HashMode)
    {
        RSA_AddOAEP(this->pImpl_->key, label, seed, labelHashMode, mgf1HashMode);
    }

    ByteArray RSA::encrypt(ByteSpan message)
    {
        return RSA_Encrypt(this->pImpl_->key, message);
    }

    ByteArray RSA::decrypt(ByteSpan cipher)
    {
        return RSA_Decrypt(this->pImpl_->key, cipher);
    }
}
