#include "inc/hash/sha.hpp"



int getSHABlockLengthByMode(SHA_MODE mode)
{
    switch(mode)
    {
        case SHA_1:
            return SHA1_BLOCK_SIZE_BYTES;
            break;
        case SHA_384:
            return SHA2_384512_BLOCK_SIZE_BYTES;
            break;
        case SHA_512:
            return SHA2_384512_BLOCK_SIZE_BYTES;
            break;
        default:
            return -1;
            break;
    }
    return -1;
}

int getSHAReturnLengthByMode(SHA_MODE mode)
{
    switch(mode)
    {
        case SHA_1:
            return 160/8;
            break;
        case SHA_384:
            return 384/8;
            break;
        case SHA_512:
            return 512/8;
            break;
        default:
            return -1;
            break;
    }
    return -1;
}