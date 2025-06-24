#include <stdio.h>
#include "cstring"
#include <vector>
#include <string>
#include <cstdint>

std::vector<uint8_t> bytePtrToVector(uint8_t *from, size_t len);
std::string bytesToHex(const std::vector<uint8_t>& bytes, bool uppercase = false);
std::string asciiToHex(const std::string& ascii, bool uppercase = false);
std::vector<uint8_t> hexToBytes(const std::string& hex);
char *printWord(uint8_t *input, size_t length, size_t blockSize);

