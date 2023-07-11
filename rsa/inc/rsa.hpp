#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <chrono>
#include <vector>
#include <iostream>


struct RSA_Params {
  BIGNUM *p, *q, *e, *n, *d, *dp, *dq, *qInv;
};

int gen_rsa_sp800_56b(RSA_Params* rsa, int nBits, BN_CTX* ctx = BN_CTX_secure_new(), bool constTime = true);
int rsa_sp800_56b_pairwise_test(RSA_Params* rsa, BN_CTX* ctx = BN_CTX_secure_new());
int rsa_roundtrip(std::string msg, RSA_Params* rsa);
int printParameter(std::string param_name, BIGNUM* num);

class Timer {
  private:
    std::chrono::_V2::high_resolution_clock::time_point startp;
    std::chrono::_V2::high_resolution_clock::time_point endp;
  public:
    void start()
    {
      startp = std::chrono::high_resolution_clock::now();
    }

    void stop()
    {
      endp = std::chrono::high_resolution_clock::now();
    }
    
    unsigned int getElapsed(bool useStop = false, int secondType = 0)
    {
      if(useStop)
        stop();
      
      if(!secondType)
        return std::chrono::duration_cast<std::chrono::microseconds>(endp - startp).count();
      else
        return std::chrono::duration_cast<std::chrono::nanoseconds>(endp - startp).count();
    }
};


class cRSA {
private:
int kBits;
public:
RSA_Params* params;
cRSA(int bits, BIGNUM *eGiven, BN_CTX* ctx = BN_CTX_secure_new())
{
  params = new RSA_Params();

  BIGNUM *p1 = nullptr, *q1 = nullptr, *lcm = nullptr, *p1q1 = nullptr, *gcd = nullptr;
  this->params->p = BN_secure_new();
  this->params->q = BN_secure_new();

  if(eGiven == NULL)
  {
    this->params->e = BN_new();
    BN_set_word(this->params->e, 65537);
  }
  else
    this->params->e = BN_dup(eGiven);

  this->params->n = BN_secure_new();
  this->params->d = BN_secure_new();
  this->params->dp = BN_secure_new();
  this->params->dq = BN_secure_new();
  this->params->qInv = BN_secure_new();
  this->kBits = bits;

   

  gen_rsa_sp800_56b(this->params, kBits);
}

unsigned char* encrypt(unsigned int *out_len, char *src, BN_CTX *ctx = BN_CTX_secure_new())
{ 
  unsigned int numBytes = strlen(src)-1;
  unsigned int maxBytes = (kBits/8);
  unsigned int numPages = (numBytes/maxBytes);
  unsigned char* returnData = (unsigned char*)malloc((numPages+1)*maxBytes);
  unsigned int returnPtr = 0;
  
  for(int i = 0; i <= numPages; i++)
  {
      BN_CTX_start(ctx);

      /* Convert the src buffer into a bignumber to be used for encryption */
      BIGNUM *originalNumber = BN_CTX_get(ctx);
      BN_bin2bn( (unsigned char*)src + (i*maxBytes), maxBytes, originalNumber);
      #ifdef LOG_CRYPTO
      std::cout << "Original Number: " << BN_bn2dec(originalNumber) <<std::endl;
      #endif
      /* Encrypt the data */
      BIGNUM *cipherNumber  = BN_CTX_get(ctx);
      BN_mod_exp(cipherNumber, originalNumber, this->params->e, this->params->n, ctx);
      #ifdef LOG_CRYPTO
      std::cout << "Encrypted Number: " << BN_bn2dec(cipherNumber) << std::endl <<std::endl;
      #endif

      /* Convert big number to binary */
      unsigned char *dataBuffer = (unsigned char*)malloc(maxBytes);
      BN_bn2bin(cipherNumber, dataBuffer);
      memcpy(returnData + (returnPtr), dataBuffer, BN_num_bytes(cipherNumber));
      
      /* Incremement the pointer and add to the output length*/
      returnPtr += BN_num_bytes(cipherNumber);
      *out_len = returnPtr;
      free(dataBuffer);
      BN_CTX_end(ctx);
  }
  BN_CTX_free(ctx);

  return returnData;
}

std::string decrypt(unsigned char *cipher, unsigned int cipher_length, BN_CTX *ctx = BN_CTX_secure_new(), bool crt = true)
{
      unsigned int maxBytes = (kBits/8);
      unsigned int numPages = (cipher_length/(maxBytes));
      std::string returnData;

      for(int i = 0; i < numPages;i++)
      {
        BN_CTX_start(ctx);
        BIGNUM* cipherNumber = BN_CTX_get(ctx);
        BIGNUM* decryptedData = BN_CTX_get(ctx);

        /* Convert */
        BN_bin2bn(cipher + (i*maxBytes), maxBytes , cipherNumber);
        
        /* Perform CRT Decryption */
        if(crt)
        { 
          BIGNUM *m1 = BN_CTX_get(ctx);
          BIGNUM *m2 = BN_CTX_get(ctx);
          BIGNUM *h = BN_CTX_get(ctx);
          BIGNUM *m1subm2 = BN_CTX_get(ctx);
          BIGNUM *hq = BN_CTX_get(ctx);

          /* m1 = c^(dP) mod p */
          BN_mod_exp(m1, cipherNumber, this->params->dp, this->params->p, ctx);
          
          /* m2 = c^(dQ) mod q */
          BN_mod_exp(m2, cipherNumber, this->params->dq, this->params->q, ctx);
          
          /* m1subm2 = (m1-m2) */
          BN_sub(m1subm2, m1, m2);
          
          /* h = qInv*(m1subm2) mod p */
          BN_mod_mul(h, this->params->qInv, m1subm2, this->params->p, ctx);
          
          /* hq = h*q */
          BN_mul(hq, h, this->params->q, ctx);
          
          /* m = m2+h*q */
          BN_add(decryptedData, m2, hq);
        }
        else
          (decryptedData, cipherNumber, this->params->d, this->params->n, ctx);

        #ifdef LOG_CRYPTO
          std::cout << "Decrypted Numbers: " << BN_bn2dec(decryptedData) <<std::endl<<std::endl<<std::endl;
        #endif
        unsigned char* dataBuffer = (unsigned char*)malloc(BN_num_bytes(decryptedData));
        BN_bn2bin(decryptedData, (unsigned char*)dataBuffer);
        returnData.append((char*)dataBuffer);
        
        free(dataBuffer);
        BN_CTX_end(ctx);
      }
    
    BN_CTX_free(ctx);
    return returnData;
}
};

