#ifndef BYTES_HPP
#define BYTES_HPP
#include <stdio.h>
#include "cstring"
#include <vector>
#include <string>
#include <cstdint>
#include <openssl/bn.h>
#include <span>

typedef std::vector<uint8_t> ByteArray;
typedef std::span<const uint8_t> ByteSpan;

//Hex helpers
std::string bytesToHex(const std::vector<uint8_t>& bytes, bool uppercase = false);
std::string asciiToHex(const std::string& ascii, bool uppercase = false);
std::vector<uint8_t> hexToBytes(const std::string& hex);
std::vector<uint8_t> hexToBytes(const std::string& hex, size_t byteLength);
BIGNUM *hexToBignum(const std::string &hex);
ByteArray asciiToByteArray(const std::string &ascii);

//Byte array helpers
std::vector<uint8_t> bytePtrToByteArray(uint8_t *from, size_t len);
std::vector<uint8_t> charToByteArray(const char* buffer, size_t length);
std::vector<uint8_t> convertBignumToByteArray(BIGNUM* cipherNumber, size_t maxBytes);
ByteArray stripPadding(const ByteArray &input);

char *printWord(uint8_t *input, size_t length, size_t blockSize);

#endif
