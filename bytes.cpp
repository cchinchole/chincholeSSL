#include "inc/utils/bytes.hpp"
#include <iomanip>
#include <openssl/bn.h>
#include <stdexcept>

std::string bytesToHex(const std::vector<uint8_t> &bytes, bool uppercase)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << (uppercase ? std::uppercase : std::nouppercase);

    for (uint8_t byte : bytes)
        oss << std::setw(2) << static_cast<int>(byte);

    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string &hex)
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

std::vector<uint8_t> hexToBytes(const std::string &hex, size_t byteLength)
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

std::vector<uint8_t> bytePtrToByteArray(uint8_t *from, size_t len)
{
    return std::vector<uint8_t>(from, from + len);
}

std::vector<uint8_t> charToByteArray(const char *buffer, size_t length)
{
    return std::vector<uint8_t>(buffer, buffer + length);
}

std::string asciiToHex(const std::string &ascii, bool uppercase)
{
    return bytesToHex(std::vector<uint8_t>(ascii.begin(), ascii.end()),
                      uppercase);
}

ByteArray asciiToByteArray(const std::string &ascii)
{
    return hexToBytes(asciiToHex(ascii));
}

std::vector<uint8_t> convertBignumToByteArray(BIGNUM *cipherNumber,
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

ByteArray stripPadding(const ByteArray &input)
{
    size_t index = 0;
    while (index < input.size() && input[index] == 0x00)
        index++;

    return ByteArray(input.begin() + index, input.end());
}

BIGNUM *hexToBignum(const std::string &hex)
{
    BIGNUM *bn = nullptr;
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

char *printWord(uint8_t *input, size_t length, size_t blockSize)
{
    int blocks = length / blockSize;
    char *output = (char *)malloc(2 * length + blocks);
    char *ptr = output;
    for (int i = 0; i < blocks; i++)
    {
        ptr += sprintf(ptr, "%s",
                       bytesToHex(bytePtrToByteArray(input, blockSize)).c_str());
        ptr += sprintf(ptr, " ");
    }
    return output;
}
