# chincholeSSL #
This is a project I did to learn about the mathematics behind cryptography during University. I followed the FIPS standard issued by NIST.
To see more details on which FIPS documents were used, refer to docs/Crypto.pdf where I break down the documents into a more readable format while citing which document they are within.

## Dependencies ##
make
openssl-devel (Atleast version 3) - Used for bignum operations
G++

## Flags ##
LOG_PARAMS : Thiss will log parameters used in key operations.

## Building ##
1. Ensure the dependencies is installed and the libraries are accessible
2. git clone https://github.com/cchinchole/chincholeSSL && cd chincholeSSL
3. make all - This will build both the lib and examples

## Examples ##
1. Examples can be run from the root directory for example LD_LIBRARY_PATH=. examples/bin/rsa

## Tests ##
1. To run a test, for example sha hashing, enter the directory and run make. (Ensure you have already built the library with make all in the root directory)
2. The tests will access the files in the vectors folder and automatically run what the library is capable of.

## Future Plans ##
1. Logger Queue. Rather than posting logs to stdout, I would like to push all errors and information to a queue that can then be wrote to a log file. This will also have the benefit of easily deciding the log levels as everything will always be pushed, but can be adjusted via a flag before being written.
2. Will rewrite this in a more *C++* style, currently this follows more C practice, but utilizes classes.
