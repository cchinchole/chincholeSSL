#include "../inc/crypto/ec.hpp"
#include "../inc/utils/logger.hpp"
#include <openssl/bn.h>

int main()
{
    cssl::Ec keypair = cssl::Ec::generate_key(cssl::EC_GROUP::P256);
    cssl::Ec keypair2 = cssl::Ec::generate_key(cssl::EC_GROUP::P256);

    ByteArray message = {'h', 'e', 'l', 'l', 'o'};
    ByteArray message2 = {'h', 'e', 'l', 'l', 'a'};
    cssl::EcSignature sig = keypair.sign(message, cssl::DIGEST_MODE::SHA_256);
    cssl::EcSignature sig2 = keypair.sign(message2, cssl::DIGEST_MODE::SHA_256);
    cssl::EcSignature sig3 = keypair2.sign(message, cssl::DIGEST_MODE::SHA_256);
    cssl::EcSignature sig4 = keypair.sign(message, cssl::DIGEST_MODE::SHA_512);
    bool valid = keypair.verify(sig, message, cssl::DIGEST_MODE::SHA_256);

    PRINT("Status of signature 1: {} expected true", valid); //Valid signature
    PRINT("Status of signature 2: {} expected false", keypair.verify(sig2, message, cssl::DIGEST_MODE::SHA_256)); //Incorrect message
    PRINT("Status of signature 3: {} expected false", keypair.verify(sig3, message, cssl::DIGEST_MODE::SHA_256)); //Incorrect keypair
    PRINT("Status of signature 4: {} expected false", keypair.verify(sig4, message, cssl::DIGEST_MODE::SHA_256)); //Hashing mismatch
    return valid ? 0 : 1;
}
