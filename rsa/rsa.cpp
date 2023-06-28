
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
#include "defs.hpp"
#include "rsa.hpp"
#include "primes.hpp"


const int kBits = 1024;
int keylen;
char *pem_key;
BIO *bio_stdout;


int printParameter(std::string param_name, BIGNUM* num)
{
  #ifdef LOG_PARAMS
  BIO_printf(bio_stdout, "%-5s", param_name.c_str());
  BIO_printf(bio_stdout, "%s", BN_bn2dec(num));
  BIO_printf(bio_stdout, "\n");
  #endif
  return 0;
}

class cRSA {
private:
RSA_Params* params;
int kBits;
public:
cRSA(int bits, BIGNUM *pp, BIGNUM *qq, BIGNUM *ee, BN_CTX* ctx = BN_CTX_new())
{
  params = new RSA_Params();
  BIGNUM *p1 = nullptr, *q1 = nullptr, *lcm = nullptr, *p1q1 = nullptr, *gcd = nullptr;
  this->params->p = BN_dup(pp);
  this->params->q = BN_dup(qq);
  this->params->e = BN_dup(ee);
  this->params->n = BN_new();
  this->params->d = BN_new();
  this->params->dp = BN_new();
  this->params->dq = BN_new();
  this->params->qInv = BN_new();
  this->kBits = bits;
  gen_rsa_sp800_56b(this->params, kBits);
}

unsigned char* encrypt(unsigned int *out_len, char *src, BN_CTX *ctx = BN_CTX_new())
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
      BIGNUM* originalNumber = BN_CTX_get(ctx);
      BN_bin2bn( (unsigned char*)src + (i*maxBytes), maxBytes, originalNumber);
      #ifdef LOG_CRYPTO
      std::cout << "Original Number: " << BN_bn2dec(originalNumber) <<std::endl;
      #endif
      /* Encrypt the data */
      BIGNUM* cipherNumber  = BN_CTX_get(ctx);
      BN_mod_exp(cipherNumber, originalNumber, this->params->e, this->params->n, ctx);
      #ifdef LOG_CRYPTO
      std::cout << "Encrypted Number: " << BN_bn2dec(cipherNumber) << std::endl <<std::endl;
      #endif`

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

std::string decrypt(unsigned char* cipher, unsigned int cipher_length, BN_CTX *ctx = BN_CTX_new(), bool crt = true)
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
          BIGNUM* m1 = BN_CTX_get(ctx);
          BIGNUM* m2 = BN_CTX_get(ctx);
          BIGNUM* h = BN_CTX_get(ctx);
          BIGNUM* m1subm2 = BN_CTX_get(ctx);
          BIGNUM* hq = BN_CTX_get(ctx);

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



int roundTrip(cRSA* rsa, char* str)
{
  unsigned int out_len = 0;
  unsigned char* cipher = rsa->encrypt(&out_len, str);
  std::string out = (rsa->decrypt(cipher, out_len).c_str());
  std::cout << "- - - - - - - - Encryption Decryption self test - - - - - - - -" << std::endl << "The inputted string: " << str << std::endl << "The outputted string: " << out << std::endl << "STRCMP returned " << strcmp( str, out.c_str()) << std::endl << "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" << std::endl;
  return 0;
}

int main(int argc, char *argv[]) {
/* Setup the openssl basic io output*/
bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

/* Generate RSA Key */
EVP_PKEY* pKey = EVP_RSA_gen(kBits);

BIO *bio = BIO_new(BIO_s_mem());
PEM_write_bio_PrivateKey(bio, pKey, NULL, NULL, 0, 0, NULL);
keylen = BIO_pending(bio);
pem_key = (char*)calloc(keylen+1, 1); // Null-terminate
BIO_read(bio, pem_key, keylen);
BIO_printf(bio_stdout, "%s\n\n\n", pem_key);

BIGNUM *my_key_p = nullptr, *my_key_q = nullptr, *my_key_d = nullptr, *my_key_e = nullptr, *my_key_n = nullptr, *my_key_dp = nullptr, *my_key_dq = nullptr;

EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_FACTOR1, &my_key_p);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_FACTOR2, &my_key_q);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_D, &my_key_d);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_E, &my_key_e);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_N, &my_key_n);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &my_key_dp);
EVP_PKEY_get_bn_param(pKey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &my_key_dq);

#ifdef LOG_PKEY
BIO_printf(bio_stdout, "Valid key: \n");
printParameter("P", my_key_p);
printParameter("Q", my_key_q);
printParameter("E", my_key_e);
printParameter("D", my_key_d);
printParameter("N", my_key_n);
printParameter("DP", my_key_dp);
printParameter("DQ", my_key_dq);
#endif


RSA_Params myRsaParams = {
  BN_new(), BN_new(), BN_new(), BN_new(), BN_new(), BN_new(), BN_new(), BN_new()
};

RSA_Params* rsaPtr = &myRsaParams;

rsaPtr->p = BN_dup(my_key_p);
rsaPtr->q = BN_dup(my_key_q);
rsaPtr->e = BN_dup(my_key_e);


#ifdef TEST_PRIMES
BN_set_word(my_key_p, 13);
BN_set_word(my_key_q, 17);
BN_set_word(my_key_e, 7);
#endif

generatePrimes(); /* Being called currently as a test for prime generation. Not suitable for setting p and q yet. */


cRSA* myRsa = new cRSA(kBits, my_key_p, my_key_q, my_key_e);

roundTrip(myRsa, "test string here! Hello World!123456789");

BIO_free_all(bio_stdout);
BIO_free_all(bio);

BN_free( my_key_p );
BN_free( my_key_q );
BN_free( my_key_d );
BN_free( my_key_e );
BN_free( my_key_n );
BN_free( my_key_dp );
BN_free( my_key_dq );
free(pKey);
delete pem_key;
return 0;
}





/*  BN_CTX:
 *    Description:
 *     Holds BigNum temporary variables that will be used by library functions.
 *     Solves the issue of expensive use with repeated subroutine calls where dynamic memory allocation is used
 *    
 *    BN_CTX_new_ex():
 *     Creates and initializes a new structure for the given library context, if left null will use the default library context
 *  
 *    BN_CTX_new():
 *     Performs the same as BN_CTX_new_ex() except it will always use the default library.
 *
 *    BN_CTX_secure_new_ex():
 *      Uses the secure heap to hold big numbers.
 *
 *    BN_CTX_start():
 *      Required to obtain IBGNUMS from the context and is ended with BN_CTX_end()
 * 
 *    BN_CTX_free():
 *      Frees the components and structure itself, call BN_CTX_end() first.
 * 
 *    Can only use a BN_CTX within a single thread of execution.
 */

/*
 * https://math.stackexchange.com/questions/2500022/do-primes-expressed-in-binary-have-more-random-bits-on-average-than-natural :: Why there are leading ones in rng generation
 * https://crypto.stanford.edu/pbc/notes/numbertheory/crt.html :: CRT
 * https://mathstats.uncg.edu/sites/pauli/112/HTML/seceratosthenes.html :: Sieve of Eratosthenes
 * http://www.cs.sjsu.edu/~stamp/CS265/SecurityEngineering/chapter5_SE/RSAmath.html :: RSA
 * https://www.di-mgt.com.au/crt_rsa.html :: CRT encryption
 * https://security.stackexchange.com/questions/176394/how-does-openssl-generate-a-big-prime-number-so-fast :: OpenSSL Generating prime numbers
 */