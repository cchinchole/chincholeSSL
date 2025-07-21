#pragma once
#include "../inc/utils/bytes.hpp"
#include "../inc/types.hpp"
#include <openssl/bn.h>

// These classes are purely internal no reason to export them.
enum class RsaPadding{
    OAEP,
    NONE
};

struct RsaPaddingParams {
    RsaPadding  mode;
    cssl::DIGEST_MODE label_hash_mode;
    cssl::DIGEST_MODE hask_hash_mode;
    ByteArray   label;
    ByteArray   seed;
};

class RsaCrtParams {
public:
    BIGNUM *dp_; 
    BIGNUM *dq_;
    BIGNUM *qinv_;
    BIGNUM *p_; 
    BIGNUM *q_;
    bool enabled_ = false;
    RsaCrtParams();
    ~RsaCrtParams();
};

class RsaKey {
public:
    int modulus_bits_ = 4096; 
    BIGNUM  *n_,
            *e_,
            *d_;
    RsaCrtParams crt_params_;
    RsaPaddingParams padding_;
    void reset_padding();
    RsaKey();
   ~RsaKey();
};
int rsa_pairwise_test(RsaKey &key);
int rsa_gen_crt_params(RsaKey &key, bool constTime);
void rsa_generate_key(RsaKey &key, int kBits);
void rsa_add_oaep(RsaKey &key, ByteSpan label, ByteSpan seed, cssl::DIGEST_MODE hashMode, cssl::DIGEST_MODE maskHashMode);
void rsa_add_oaep(RsaKey &key, ByteSpan label, cssl::DIGEST_MODE hashMode, cssl::DIGEST_MODE maskHashMode);
ByteArray rsa_encrypt(RsaKey &key, std::span<const uint8_t> src);
ByteArray rsa_decrypt(RsaKey &key, std::span<const uint8_t> cipher);
ByteArray rsa_mgf1(std::span<const uint8_t> seed, size_t maskLen, cssl::DIGEST_MODE shaMode = cssl::DIGEST_MODE::SHA_1);