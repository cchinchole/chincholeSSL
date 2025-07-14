# chincholeSSL #
This is a project I did to learn about the mathematics behind cryptography during University. I followed the FIPS standard issued by NIST.
To see more details on which FIPS documents were used, refer to docs/Crypto.pdf where I break down the documents into a more readable format while citing which document they are within.

## Dependencies ##
2. openssl3 headers (Pkg is usually openssl-devel)
4. G++ (14+)
1. make
3. pkg-config

## Flags ##
1. Makefile : DEBUG, setting this to true will output verbose parameters and steps during encryption / decryption. (Extremely unsafe, only for dev use)

## Building and installing ##
1. Ensure the dependencies is installed and the libraries are accessible
2. git clone https://github.com/cchinchole/chincholeSSL && cd chincholeSSL
3. make all - This will build both the lib and examples
4. make install - Installs the libraries to /usr/local/lib and /usr/local/include

## Example Usage ##
*For more details, review the examples folder*
### AES ###
```cpp
    #include "cssl/crypto/aes.hpp"
    #include "cssl/utils/bytes.hpp"

    AES_CTX ctx(AES_MODE::CBC, AES_KEYSIZE::m128);
    std::string aes_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv = "000102030405060708090a0b0c0d0e0f";
    std::string cbc_kat = "3243f6a8885a308d313198a2e0370734";

    ByteArray buffer = hexToBytes(cbc_kat);
    AES_KeyExpansion(ctx, hexToBytes(aes_kat_key));
    AES_SetIV(ctx, hexToBytes(aes_iv));
    ByteArray cipher = AES_Encrypt(ctx, buffer);
    ByteArray decipher = AES_Decrypt(ctx, cipher);
```

### RSA ###
```cpp
     #include "cssl/crypto/rsa.hpp"
     #include "cssl/utils/bytes.hpp"

     cRSAKey key;
     RSA_GenerateKey(key);
     ByteArray cipher = RSA_Encrypt(key, str);
     ByteArray decrypt = RSA_Decrypt(key, cipher);
```

### EC ###
```cpp
    #include "cssl/crypto/ec.hpp"
    #include "cssl/utils/bytes.hpp"
    cECKey key(ECGroup::P256);
    cECSignature sig;
    ByteArray msg = hexToBytes("aabbccddeeffaabbcceeddeedd11001100");
    EC_Generate_KeyPair(key);
    EC_GenerateSignature(key, sig, msg, DIGEST_MODE::SHA_512);
    EC_VerifySignature(key, sig, msg, DIGEST_MODE::SHA_512); //Returns 0 on success
```

## Tests ##
1. To run a test, for example sha hashing, enter the directory and run "make run". (Ensure you have already built the library with make all in the root directory)
2. The tests will access the files in the vectors folder and automatically run what the library is capable of.

## Future Plans ##
1. Update SHA to using ByteArray for definitions.
2. Update all interfaces to use a more C++ style.
3. Input PEM files
