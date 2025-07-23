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
*For more details, review the examples folder*\
Note: you can use the global include header "cssl/cssl.hpp or include the modules needed directly.\
### AES ###
```cpp
    #include "cssl/crypto/aes.hpp"
    #include "cssl/utils/bytes.hpp"

    std::string aes_kat_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv_key = "000102030405060708090a0b0c0d0e0f";
    std::string cbc_kat = "3243f6a8885a308d313198a2e0370734";
    cssl::Aes aes(cssl::AES_MODE::CBC, cssl::AES_KEYSIZE::m128);

    aes.load_key(aes_kat_key, aes_iv_key);

    ByteArray buffer = hex_to_bytes(cbc_kat);
    ByteArray cipher = aes.encrypt(buffer);
    ByteArray decipher = aes.decrypt(cipher);
```

### RSA ###
```cpp
    #include "cssl/crypto/rsa.hpp"
    #include "cssl/utils/bytes.hpp"

    cssl::Rsa rsaOAEP(1024);

    // Load the key like this
    rsaOAEP.load_public_key(modulus, publicExponent);
    rsaOAEP.load_private_key(modulus, privateExponent);

    // Additionally add and enable CRT
    // ex1: dP, ex2: dQ, coe: qInv
    rsaOAEP.load_crt(P, Q, ex1, ex2, coe);

    // Or generate the key using the primes
    //rsaOAEP.from(P, Q, publicExponent);

    // Or completely generate a new key.
    //rsaOAEP.generate_key();
    
    //No need to specify the label can leave it empty, same with the seed. This is mostly for ensuring a constant Encode.
    rsaOAEP.add_oaep({}, hex_to_bytes("18b776ea21069d69776a33e96bad48e1dda0a5ef"), cssl::DIGEST_MODE::SHA_1, cssl::DIGEST_MODE::SHA_1);

    //Leaving off the addOAEP will use raw RSA.
    ByteArray c = rsaOAEP.encrypt(hexToBytes("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34"));
    ByteArray d = rsaOAEP.decrypt(c);
```

### EC ###
```cpp
    #include "cssl/crypto/ec.hpp"
    #include "cssl/utils/bytes.hpp"

    cssl::Ec ec = cssl::Ec::generate_key(cssl::EC_GROUP::P256);
    //Ec ec = Ec::from(group, "d", "px", "py");
    ByteArray msg = hex_to_bytes("aabbccddeeffaabbcceeddeedd11001100");
    cssl::EcSignature sig = ec.sign(msg, cssl::DIGEST_MODE::SHA_256);
    bool verification = ec.verify(sig, msg, cssl::DIGEST_MODE::SHA_256);
```

### HASH ###
```cpp
    #include "../inc/hash/hash.hpp"

    //Example for oneshot hashing. For SHAKE use Hasher::xof
    ByteArray msg = hex_to_bytes(ascii_to_hex("Hello World!"));
    ByteArray hash = cssl::Hasher::hash(msg, cssl::DIGEST_MODE::SHA_1);

    //Example for HMAC
    ByteArray key = hex_to_bytes(ascii_to_hex("HelloKey!"));
    ByteArray hmacDigest = cssl::Hasher::hmac(msg, key, cssl::DIGEST_MODE::SHA_3_512);

    //Example using update + SHAKE
    cssl::Hasher h(cssl::DIGEST_MODE::SHA_3_SHAKE_128);
    h.update(msg);
    ByteArray hash = h.xof(72); //72 being the amount of bytes to output.
```
### Building an application ###
```
    g++ -std=c++23 -I/usr/local/include main.cpp -o main -L/usr/local/lib -lcssl -lssl -lcrypto
    #or statically
    g++ -std=c++23 -I/usr/local/include main.cpp -o main -L/usr/local/lib -l:libcssl.a -lssl -lcrypto
```

## Tests ##
1. To run a test, for example sha hashing, enter the directory and run "make run". (Ensure you have already built the library with make all in the root directory)
2. The tests will access the files in the vectors folder and automatically run what the library is capable of.

## Libraries Used ##
- [OpenSSL](https://github.com/openssl/openssl) - Cryptographic library for secure communication.
- [nlohmann/json](https://github.com/nlohmann/json) - Header-only JSON library for C++.
