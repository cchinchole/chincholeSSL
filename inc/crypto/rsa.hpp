#pragma once
#include <stdio.h>
#include "../utils/bytes.hpp"
#include "../types.hpp"

namespace cssl {
class Rsa {
    private:
        struct Impl;
        Impl *pimpl_;
    public:
        explicit Rsa(size_t bits);
        ~Rsa();
        bool is_crt_enabled();
        void from(std::string hex_p, std::string hex_q, std::string hex_e);
        void load_public_key(std::string hex_n, std::string hex_e);
        void load_private_key(std::string hex_n, std::string hex_d);
        void load_crt(std::string hex_p, std::string hex_q, std::string hex_dp, std::string hex_dq, std::string hex_qinv);
        void generate_key();
        void clear_padding();
        void add_oaep(ByteSpan label, DIGEST_MODE label_hash_mode, DIGEST_MODE mgf1_hash_mode);
        void add_oaep(ByteSpan label, ByteSpan seed, DIGEST_MODE label_hash_mode, DIGEST_MODE mgf1_hash_mode);
        ByteArray encrypt(ByteSpan message);
        ByteArray decrypt(ByteSpan cipher);
};
}
