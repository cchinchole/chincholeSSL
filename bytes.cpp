#include "inc/utils/bytes.hpp"
#include <iomanip>
#include <openssl/bn.h>
#include <stdexcept>

std::string bytes_to_hex(const std::vector<uint8_t> &bytes, bool uppercase)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << (uppercase ? std::uppercase : std::nouppercase);

    for (uint8_t byte : bytes)
        oss << std::setw(2) << static_cast<int>(byte);

    return oss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string &hex)
{
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Invalid hex string");

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        std::string byteStr = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::vector<uint8_t> hex_to_bytes(const std::string &hex, size_t byteLength)
{
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Invalid hex string");

    std::vector<uint8_t> bytes;
    bytes.reserve(byteLength);

    for (size_t i = 0; i < byteLength; ++i)
    {
        std::string byteStr = hex.substr(i * 2, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::vector<uint8_t> byteptr_to_bytearray(uint8_t *from, size_t len)
{
    return std::vector<uint8_t>(from, from + len);
}

std::vector<uint8_t> char_to_bytearray(const char *buffer, size_t length)
{
    return std::vector<uint8_t>(buffer, buffer + length);
}

std::string ascii_to_hex(const std::string &ascii, bool uppercase)
{
    return bytes_to_hex(std::vector<uint8_t>(ascii.begin(), ascii.end()),
                      uppercase);
}

ByteArray ascii_to_bytearray(const std::string &ascii)
{
    return hex_to_bytes(ascii_to_hex(ascii));
}

std::vector<uint8_t> bignum_to_bytearray(BIGNUM *cipherNumber,
                                              size_t maxBytes)
{

    std::vector<uint8_t> vec;
    unsigned char *dataBuffer = (unsigned char *)malloc(maxBytes);

    if (!dataBuffer)
        return vec;

    int bytesWritten = BN_bn2bin(cipherNumber, dataBuffer);
    if (bytesWritten > 0 && static_cast<size_t>(bytesWritten) <= maxBytes)
    {
        vec.assign(dataBuffer, dataBuffer + bytesWritten);
    }

    free(dataBuffer);
    return vec;
}

ByteArray strip_padding(const ByteArray &input)
{
    size_t index = 0;
    while (index < input.size() && input[index] == 0x00)
        index++;

    return ByteArray(input.begin() + index, input.end());
}

void hex_to_bignum(BIGNUM *bn, const std::string &str)
{
    BIGNUM *bnVal = BN_new();
    BN_hex2bn(&bnVal, str.c_str());
    BN_copy(bn, bnVal);
    BN_free(bnVal);
}

BIGNUM *hex_to_bignum(const std::string &hex)
{
    BIGNUM *bn = nullptr;
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

char *print_word(uint8_t *input, size_t length, size_t blockSize)
{
    int blocks = length / blockSize;
    char *output = (char *)malloc(2 * length + blocks);
    char *ptr = output;
    for (int i = 0; i < blocks; i++)
    {
        ptr +=
            sprintf(ptr, "%s",
                    bytes_to_hex(byteptr_to_bytearray(input, blockSize)).c_str());
        ptr += sprintf(ptr, " ");
    }
    return output;
}
