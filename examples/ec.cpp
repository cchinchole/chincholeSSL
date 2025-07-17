#include "../inc/cssl.hpp"
#include <openssl/bn.h>

int main()
{
    cSSL::ECKeyPair keypair = cSSL::ECKeyPair::Generate(ECGroup::P256);
    cSSL::ECKeyPair keypair2 = cSSL::ECKeyPair::Generate(ECGroup::P256);

    ByteArray message = {'h', 'e', 'l', 'l', 'o'};
    ByteArray message2 = {'h', 'e', 'l', 'l', 'a'};
    cSSL::ECSignature sig = keypair.sign(message, DIGEST_MODE::SHA_256);
    cSSL::ECSignature sig2 = keypair.sign(message2, DIGEST_MODE::SHA_256);
    cSSL::ECSignature sig3 = keypair2.sign(message, DIGEST_MODE::SHA_256);
    cSSL::ECSignature sig4 = keypair.sign(message, DIGEST_MODE::SHA_512);
    bool valid = keypair.verify(sig, message, DIGEST_MODE::SHA_256);

    PRINT("Status of signature 1: {} expected true", valid); //Valid signature
    PRINT("Status of signature 2: {} expected false", keypair.verify(sig2, message, DIGEST_MODE::SHA_256)); //Incorrect message
    PRINT("Status of signature 3: {} expected false", keypair.verify(sig3, message, DIGEST_MODE::SHA_256)); //Incorrect keypair
    PRINT("Status of signature 4: {} expected false", keypair.verify(sig4, message, DIGEST_MODE::SHA_256)); //Hashing mismatch
    return valid ? 0 : 1;
}
