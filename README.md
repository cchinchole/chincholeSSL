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

## Examples ##
1. Build the examples using either "make" within the example directory or "make -C examples" from the root.
2. Examples are outputted to the examples/bin directory.
3. These are statically linked to the library.

## Tests ##
1. To run a test, for example sha hashing, enter the directory and run "make run". (Ensure you have already built the library with make all in the root directory)
2. The tests will access the files in the vectors folder and automatically run what the library is capable of.

## Future Plans ##
1. AES rewritten to input and output a ByteArray *vector<uint8_t>*
2. AES modes CFB, OFB
3. Add nice codeblocks to README to show quick examples of usage
4. Input PEM files
