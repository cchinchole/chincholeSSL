#include <stdio.h>
#include <memory>

/* using a byte array[4] to act as a word to make shifting data easier */


#define nB 4    /* Standard for FIPS 197 */
#define AES_BlockSize 16 /* in bytes */

/* Can use this to cast the buffer without having to manually set the 16 bytes */
//using state_t = uint8_t[4][4];


enum AES_MODE {
    AES_CBC_128,
    AES_CBC_192,
    AES_CBC_256
};

class AES_CTX {
    public:
        AES_MODE mode;
        uint8_t state[nB][nB];  
        uint8_t w[240];             //Round Key; setting to maximum size for AES256
        uint8_t iv[AES_BlockSize];  //IV For CBC
};


int getNR(AES_MODE mode);
int getNK(AES_MODE mode);
int FIPS_197_5_2_KeyExpansion(AES_CTX *ctx, uint8_t *key);
int FIPS_197_5_1_Cipher(AES_CTX *ctx);