#include <stdio.h>
#include "memory"
#include "malloc.h"
#include "cstring"
#include <cstdint>

unsigned char *byteArrToHexArr(unsigned char *bytes, size_t byte_len);
uint8_t *scanHex(char *str, int bytes);
char *printWord(uint8_t *input, size_t length, size_t blockSize);
