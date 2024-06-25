build:
	g++ -o main -g -O0 -fdiagnostics-color=always -lssl -lcrypto global.cpp bytes.cpp sha1.cpp sha256.cpp sha384512.cpp sha3.cpp sha.cpp hmac.cpp aes.cpp rand.cpp time.cpp rsa.cpp ec.cpp primes.cpp test.cpp main.cpp
