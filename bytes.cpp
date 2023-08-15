#include "inc/utils/bytes.hpp"
unsigned char *byteArrToHexArr(unsigned char *bytes, size_t byte_len)
{

    unsigned char *dest = (unsigned char *)malloc(2 * byte_len + 1);
    if (!dest)
        return NULL;

    unsigned char *p = dest;
    for (size_t i = 0; i < byte_len; ++i)
    {
        p += sprintf((char *)p, "%02hhX", bytes[i]);
    }
    return dest;
}

uint8_t *scanHex(char *str, int bytes)
{
    uint8_t *ret = (uint8_t *)malloc(bytes);
    memset(ret, 0, bytes);

    for (int i = 0, i2 = 0; i < bytes; i++, i2 += 2)
    {
        // get value
        for (int j = 0; j < 2; j++)
        {
            ret[i] <<= 4;
            uint8_t c = str[i2 + j];
            if (c >= '0' && c <= '9')
            {
                ret[i] += c - '0';
            }
            else if (c >= 'a' && c <= 'f')
            {
                ret[i] += c - 'a' + 10;
            }
            else if (c >= 'A' && c <= 'F')
            {
                ret[i] += c - 'A' + 10;
            }
            else
            {
                free(ret);
                return NULL;
            }
        }
    }

    return ret;
}

char *printWord(uint8_t *input, size_t length, size_t blockSize)
{
    int blocks = length / blockSize;
    char *output = (char *)malloc(2 * length + blocks);
    char *ptr = output;
    for (int i = 0; i < blocks; i++)
    {
        ptr += sprintf(ptr, "%s", (char *)byteArrToHexArr(input + (i * blockSize), blockSize));
        ptr += sprintf(ptr, " ");
    }
    return output;
}