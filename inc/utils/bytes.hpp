#ifndef BYTES_HPP
#define BYTES_HPP
#include <stdio.h>
#include "cstring"
#include <vector>
#include <string>
#include <cstdint>
#include <openssl/bn.h>

typedef std::vector<uint8_t> ByteArray;
std::vector<uint8_t> bytePtrToVector(uint8_t *from, size_t len);
std::string bytesToHex(const std::vector<uint8_t>& bytes, bool uppercase = false);
std::string asciiToHex(const std::string& ascii, bool uppercase = false);
std::vector<uint8_t> charToVector(const char* buffer, size_t length);
std::vector<uint8_t> hexToBytes(const std::string& hex);
std::vector<uint8_t> convertBignumToVector(BIGNUM* cipherNumber, size_t maxBytes);
ByteArray stripPadding(const ByteArray &input);
char *printWord(uint8_t *input, size_t length, size_t blockSize);

#endif
