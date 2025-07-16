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

    std::string aes_kat_key = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string aes_iv_key = "000102030405060708090a0b0c0d0e0f";
    std::string cbc_kat = "3243f6a8885a308d313198a2e0370734";
    AES ctx(AES_MODE::CBC, AES_KEYSIZE::m128);

    aes.addKey(aes_kat_key, aes_iv_key);

    ByteArray buffer = hexToBytes(cbc_kat);
    ByteArray cipher = aes.encrypt(buffer);
    ByteArray decipher = aes.decrypt(cipher);
```

### RSA ###
```cpp
    #include "cssl/crypto/rsa.hpp"
    #include "cssl/utils/bytes.hpp"
    cSSL::RSA rsaOAEP(1024);

    // Load the key like this
    rsaOAEP.loadPublicKey(modulus, publicExponent);
    rsaOAEP.loadPrivateKey(modulus, privateExponent);

    // Additionally add and enable CRT
    // ex1: dP, ex2: dQ, coe: qInv
    rsaOAEP.loadCRT(P, Q, ex1, ex2, coe);

    // Or generate the key using the primes
    //rsaOAEP.fromPrimes(P, Q, publicExponent);

    // Or completely generate a new key.
    //rsaOAEP.generateKey();
    
    //No need to specify the label can leave it empty, same with the seed. This is mostly for ensuring a constant Encode.
    rsaOAEP.addOAEP({}, hexToBytes("18b776ea21069d69776a33e96bad48e1dda0a5ef"), DIGEST_MODE::SHA_1, DIGEST_MODE::SHA_1);

    //Leaving off the addOAEP will use raw RSA.
    ByteArray c = rsaOAEP.encrypt(hexToBytes("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34"));
    ByteArray d = rsaOAEP.decrypt(c);
```

### EC ###
```cpp
    #include "cssl/crypto/ec.hpp"
    #include "cssl/utils/bytes.hpp"
    ECKeyPair keypair = ECKeyPair::Generate(ECGroup::P256);
    //ECKeyPair keypair = ECKeyPair::From(group, "d", "px", "py");
    ByteArray msg = hexToBytes("aabbccddeeffaabbcceeddeedd11001100");
    ECSignature sig = keypair.sign(msg, DIGEST_MODE::SHA_256);
    bool verification = keypair.verify(sig, msg, DIGEST_MODE::SHA_256);
```
### Building an application ###
```
	g++ -std=c++23 -L/usr/local/lib -lcssl -lcrypto -lssl -I/usr/local/include main.cpp -o main 
    #or statically
	g++ -std=c++23 -L/usr/local/lib -l:libcssl.a -lcrypto -lssl -I/usr/local/include main.cpp -o main
    LD_LIBRARY_PATH=/usr/local/lib ./main
```

## Tests ##
1. To run a test, for example sha hashing, enter the directory and run "make run". (Ensure you have already built the library with make all in the root directory)
2. The tests will access the files in the vectors folder and automatically run what the library is capable of.

## Future Plans ##
1. Update SHA to using ByteArray for definitions.
2. Update all interfaces to use a more C++ style.
3. Input PEM files

## Libraries Used ##
- [OpenSSL](https://github.com/openssl/openssl) - Cryptographic library for secure communication.
- [nlohmann/json](https://github.com/nlohmann/json) - Header-only JSON library for C++.
