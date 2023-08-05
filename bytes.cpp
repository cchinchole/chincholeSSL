#include "inc/utils/bytes.hpp"
#include "memory"
#include "malloc.h"

unsigned char *byteArrToHexArr(unsigned char *bytes, size_t byte_len)
{

    unsigned char *dest = (unsigned char*) malloc(2*byte_len + 1);
    if (!dest) return NULL;

    unsigned char *p = dest;
    for (size_t i = 0;  i < byte_len;  ++i) {
        p += sprintf((char*)p, "%02hhX", bytes[i]);
    }
    return dest;
}