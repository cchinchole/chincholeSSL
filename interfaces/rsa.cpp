#include "../inc/crypto/rsa.hpp"
#include "../internal/rsa.hpp"
#include "../inc/utils/bytes.hpp"
#include <openssl/bn.h>


namespace cssl {

    struct Rsa::Impl {
        RsaKey ctx;
    };

    Rsa::Rsa(size_t bits) : pimpl_(new Impl())
    {
        pimpl_->ctx.modulus_bits_ = bits;
    }

    Rsa::~Rsa()
    {
        delete pimpl_;
    }

    bool Rsa::is_crt_enabled()
    {
        return pimpl_->ctx.crt_params_.enabled_;
    }

    void Rsa::from(std::string hex_p, std::string hex_q, std::string hex_e)
    {
        hex_to_bignum(pimpl_->ctx.crt_params_.p_, hex_p);
        hex_to_bignum(pimpl_->ctx.crt_params_.q_, hex_q);
        hex_to_bignum(pimpl_->ctx.e_, hex_e);
        rsa_gen_crt_params(pimpl_->ctx, true);
    }
    
    void Rsa::load_public_key(std::string hex_n, std::string hex_e)
    {
        hex_to_bignum(pimpl_->ctx.n_, hex_n);
        hex_to_bignum(pimpl_->ctx.e_, hex_e);
    }
    void Rsa::load_private_key(std::string hex_n, std::string hex_d)
    {
        hex_to_bignum(pimpl_->ctx.n_, hex_n);
        hex_to_bignum(pimpl_->ctx.d_, hex_d);
    }
    void Rsa::load_crt(std::string hex_p, std::string hex_q, std::string hex_dp, std::string hex_dq, std::string hex_qinv)
    {
        hex_to_bignum(pimpl_->ctx.crt_params_.p_, hex_p);
        hex_to_bignum(pimpl_->ctx.crt_params_.q_, hex_q);
        hex_to_bignum(pimpl_->ctx.crt_params_.dp_, hex_dp);
        hex_to_bignum(pimpl_->ctx.crt_params_.dq_, hex_dq);
        hex_to_bignum(pimpl_->ctx.crt_params_.qinv_, hex_qinv);
        pimpl_->ctx.crt_params_.enabled_ = true;
    }
    
    void Rsa::generate_key()
    {
        rsa_generate_key(pimpl_->ctx, pimpl_->ctx.modulus_bits_);
    }

    void Rsa::clear_padding()
    {
        pimpl_->ctx.reset_padding();
    }

    void Rsa::add_oaep(ByteSpan label, DIGEST_MODE label_hash_mode, DIGEST_MODE mgf1_hash_mode)
    {
        rsa_add_oaep(pimpl_->ctx, label, label_hash_mode, mgf1_hash_mode);
    }

    void Rsa::add_oaep(ByteSpan label, ByteSpan seed, DIGEST_MODE label_hash_mode, DIGEST_MODE mgf1_hash_mode)
    {
        rsa_add_oaep(pimpl_->ctx, label, seed, label_hash_mode, mgf1_hash_mode);
    }

    ByteArray Rsa::encrypt(ByteSpan message)
    {
        return rsa_encrypt(pimpl_->ctx, message);
    }

    ByteArray Rsa::decrypt(ByteSpan cipher)
    {
        return rsa_decrypt(pimpl_->ctx, cipher);
    }
}
