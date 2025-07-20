#pragma once
#include <stdio.h>
#include "../utils/bytes.hpp"
#include "../hash/hash.hpp"

namespace CSSL {
class RSA {
    private:
        class Impl_;
        Impl_ *pImpl_;
    public:
        RSA(size_t bits);
        ~RSA();
        bool isCRTEnabled();
        void fromPrimes(std::string hexP, std::string hexQ, std::string hexE);
        void loadPublicKey(std::string hexModulus, std::string hexPublicExponent);
        void loadPrivateKey(std::string hexModulus, std::string hexPrivateExponent);
        void loadCRT(std::string hexP, std::string hexQ, std::string hexDP, std::string hexDQ, std::string hexQinv);
        void generateKey();
        void clearPadding();
        void addOAEP(ByteSpan label, DIGEST_MODE labelHashMode, DIGEST_MODE mgf1HashMode);
        void addOAEP(ByteSpan label, ByteSpan seed, DIGEST_MODE labelHashMode, DIGEST_MODE mgf1HashMode);
        ByteArray encrypt(ByteSpan message);
        ByteArray decrypt(ByteSpan cipher);
};
}
