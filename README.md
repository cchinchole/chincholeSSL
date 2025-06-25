# chincholeSSL #
This is a project I did to learn about the mathematics behind cryptography during University. I followed the FIPS standard issued by NIST.
To see more details on which FIPS documents were used, refer to docs/Crypto.pdf where I break down the documents into a more readable format while citing which document they are within.

## Dependencies ##
1. make
2. openssl-devel (Atleast version 3) - Used for bignum operations
3. pkg-config
4. G++

## Flags ##
1. LOG_PARAMS : Thiss will log parameters used in key operations.
2. AES_LOG : Will log the state in the AES ctx for debugging.

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
1. Logger Queue. Rather than posting logs to stdout, I would like to push all errors and information to a queue that can then be wrote to a log file. This will also have the benefit of easily deciding the log levels as everything will always be pushed, but can be adjusted via a flag before being written.
2. Will rewrite this in a more *C++* style, currently this follows more C practice, but utilizes classes.
