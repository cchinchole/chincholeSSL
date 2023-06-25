
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


const int kBits = 1024;
int keylen;
char *pem_key;
BIO *bio_stdout;


struct RSA_Params {
  BIGNUM *p, *q, *e, *n = BN_new(), *d = BN_new(), *dp = BN_new(), *dq = BN_new(), *qInv = BN_new();
};

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
    
    unsigned int getElapsed(bool useStop = false)
    {
      if(useStop)
        stop();
      return std::chrono::duration_cast<std::chrono::microseconds>(endp - startp).count();
    }
};


int gen_rsa_sp800_56b(RSA_Params* rsa, int nBits, BN_CTX* ctx = BN_CTX_new());
int rsa_sp800_56b_pairwise_test(RSA_Params* rsa, BN_CTX* ctx = BN_CTX_new());
int rsa_roundtrip(std::string msg, RSA_Params* rsa);
int printParameter(std::string param_name, BIGNUM* num);
Timer t;

int printParameter(std::string param_name, BIGNUM* num)
{
  #ifdef PRINT_PARAMS
  BIO_printf(bio_stdout, "%-5s", param_name.c_str());
  BIO_printf(bio_stdout, "%s", BN_bn2dec(num));
  BIO_printf(bio_stdout, "\n");
  #endif
  return 0;
}

class cRSA {
private:
BIGNUM  *p, *q, *e, *n, *d, *dp, *dq, *qInv;
int kBits;
public:
cRSA(int bits, BIGNUM *pp, BIGNUM *qq, BIGNUM *ee, BN_CTX* ctx = BN_CTX_new())
{
  
  BIGNUM *p1 = nullptr, *q1 = nullptr, *lcm = nullptr, *p1q1 = nullptr, *gcd = nullptr;
  this->p = BN_dup(pp);
  this->q = BN_dup(qq);
  this->e = BN_dup(ee);
  this->n = BN_new();
  this->d = BN_new();
  this->dp = BN_new();
  this->dq = BN_new();
  this->qInv = BN_new();
  this->kBits = bits;

  BN_CTX_start(ctx);
  p1 = BN_CTX_get(ctx);
  q1 = BN_CTX_get(ctx);
  lcm = BN_CTX_get(ctx);
  p1q1 = BN_CTX_get(ctx);
  gcd = BN_CTX_get(ctx);

  printParameter("P", this->p);
  printParameter("Q", this->q);
  printParameter("E", this->e);

  /* Step 1: Find the least common multiple of (p-1, q-1) */
  BN_sub(p1, this->p, BN_value_one());  /* p - 1 */
  BN_sub(q1, this->q, BN_value_one());  /* q - 1 */
  BN_mul(p1q1, p1, q1, ctx);      /* (p-1)(q-1)*/
  BN_gcd(gcd, p1, q1, ctx);       
  BN_div(lcm, NULL, p1q1, gcd, ctx);
  printParameter("GCD", gcd);
  printParameter("LCM", lcm);

  /* Step 2: d = e^(-1) mod(LCM[(p-1)(q-1)]) */
  /* Keep repeating incase the bitsize is too short */
 
  for(;;)
  {
      BN_mod_inverse(this->d, this->e, lcm, ctx);
      printParameter("D", this->d);
      #ifdef DO_CHECKS
        if (!(BN_num_bits(this->d) <= (nBits >> 1)))
          break;
      #else
        break;
      #endif
  }

  /* Step 3: n = pq */
  BN_mul(this->n, this->p, this->q, ctx);
  printParameter("N", this->n);

  t.start();
  /* Step 4: dP = d mod(p-1)*/
  BN_mod(this->dp, this->d, p1, ctx);

  /* Step 5: dQ = d mod(q-1)*/
  BN_mod(this->dq, this->d, q1, ctx);

  /* Step 6: qInv = q^(-1) mod(p) */
  BN_mod_inverse(this->qInv, this->q, this->p, ctx);

  printf("Took: %dms to generate CRT parameters.\n", t.getElapsed(true));

  printParameter("DP", this->dp);
  printParameter("DQ", this->dq);
  printParameter("QINV", this->qInv);

  

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
}

int encrypt(BIGNUM** desti, int *len, char *src, BN_CTX *ctx = BN_CTX_new())
{
  int numBytes = strlen(src);
  int maxBytes = (kBits/8)-1;
  int numPages = ((numBytes)/maxBytes);
  int msgPtr = 0;
  BIGNUM* data = BN_new();
  BIGNUM* dest = BN_new();
  BN_CTX_start(ctx);
  for(int i = 0; i <= numPages; i++)
  {
    char* msgBlockData;
    if( (numBytes-msgPtr) >= maxBytes ){
      msgBlockData = (char*)malloc( maxBytes );
      strncpy(msgBlockData, src + msgPtr, (maxBytes)  );
    }
    else{
      msgBlockData = (char*)malloc( numBytes-msgPtr+1 );
      strncpy(msgBlockData, src + msgPtr, numBytes-msgPtr+1);
    }

    if((numBytes-msgPtr) >= maxBytes)
      BN_bin2bn((unsigned char*)msgBlockData, (maxBytes), data);
    else
      BN_bin2bn((unsigned char*)msgBlockData, strlen(msgBlockData)+1, data);

      BN_mod_exp(dest, data, this->e, this->n, ctx);

      desti[i] = BN_dup(dest);
      msgPtr+=(maxBytes);
      delete msgBlockData;
  }
  *len = numBytes;
  BN_CTX_end(ctx);
  return 0;
}

int decrypt(std::string* data, int length, BIGNUM** src, BN_CTX *ctx = BN_CTX_new())
{
  int numBytes = length;
  int maxBytes = (kBits/8)-1;
  int numPages = ((numBytes-1)/maxBytes);
  int msgPtr = 0;
  BN_CTX_start(ctx);
  printf("\nlength: %d\n", numBytes);
  for(int i = 0; i <= numPages; i++)
  {
      BIGNUM* temp = BN_CTX_get(ctx);
      printf("\n{Decryption} Performing operation on page [ %d ]\n", i);
      BN_mod_exp(temp, src[i], this->d, this->n, ctx);
      char* temp2 = (char*)malloc( BN_num_bytes(temp) );
      BN_bn2bin(temp, (unsigned char*)temp2);
      printf("\nDECRYPTED HERE: %s\n", temp2);
      data->append(temp2);
      free(temp2);
  }
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return 0;
}

};

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
BN_set_word(rsaPtr->p, 13);
BN_set_word(rsaPtr->q, 17);
BN_set_word(rsaPtr->e, 7);
#endif

//gen_rsa_sp800_56b(rsaPtr, kBits);
//rsa_roundtrip("bbsWcMTs5H7U4m6m5VrNsaV1NBpK9NIh8OlgNTYeKVGKHbrjWd69wwcpH0jDXXeulYtFqPKtjEbTjqlN8hhZFzimHciLjJivexPaNbuJldqRrIZ5r6C4I5ykVF7X93HZzFCwAfjxToF8gZ1RfulaO02HFa954fpu2alc7CGB6lcEwSslUJaDM4pLQwJEwF5mFJZp6P1WzCxlzQY9WaVOcz4P8BPFgEwEgkVxajO9547A5yJtc3rE9RNuGNGSQZ4w", rsaPtr);

cRSA* myRsa = new cRSA(kBits, my_key_p, my_key_q, my_key_e);

BIGNUM* cipher = BN_new();
std::string output = "";
int length = 0;
myRsa->encrypt(&cipher, &length, "bbsWcMTs5H7U4m6m5VrNsaV1NBpK9NIh8OlgNTYeKVGKHbrjWd69wwcpH0jDXXeulYtFqPKtjEbTjqlN8hhZFzimHciLjJivexPaNbuJldqRrIZ5r6C4I5ykVF7X93HZzFCwAfjxToF8gZ1RfulaO02HFa954fpu2alc7CGB6lcEwSslUJaDM4pLQwJEwF5mFJZp6P1WzCxlzQY9WaVOcz4P8BPFgEwEgkVxajO9547A5yJtc3rE9RNuGNGSQZ4w");
//printf("\nCipher2: %s\n", BN_bn2dec(cipher));
//myRsa->decrypt(&output, length, &cipher);
//printf("\nFinal point: %s %d\n", output.c_str(), strcmp(output.c_str(), "bbsWcMTs5H7U4m6m5VrNsaV1NBpK9NIh8OlgNTYeKVGKHbrjWd69wwcpH0jDXXeulYtFqPKtjEbTjqlN8hhZFzimHciLjJivexPaNbuJldqRrIZ5r6C4I5ykVF7X93HZzFCwAfjxToF8gZ1RfulaO02HFa954fpu2alc7CGB6lcEwSslUJaDM4pLQwJEwF5mFJZp6P1WzCxlzQY9WaVOcz4P8BPFgEwEgkVxajO9547A5yJtc3rE9RNuGNGSQZ4w"));

BIO_free_all(bio_stdout);
BIO_free_all(bio);

BN_free(cipher);
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



int rsa_decrypt_without_crt(BIGNUM* data, BIGNUM* cipher, RSA_Params* rsa, BN_CTX* ctx = BN_CTX_new())
{
  /* Decryption: msg = cipher^d mod n */
  BN_mod_exp(data, cipher, rsa->d, rsa->n, ctx);
  BN_CTX_free(ctx);
  return 0;
}

int rsa_decrypt_with_crt(BIGNUM* data, BIGNUM* cipher, RSA_Params* rsa, BN_CTX* ctx = BN_CTX_new())
{
  /* Using CRT for decryption */
  BN_CTX_start(ctx);
  BIGNUM* m1 = BN_CTX_get(ctx);
  BIGNUM* m2 = BN_CTX_get(ctx);
  BIGNUM* h = BN_CTX_get(ctx);
  BIGNUM* m1subm2 = BN_CTX_get(ctx);
  BIGNUM* hq = BN_CTX_get(ctx);

  /* m1 = c^(dP) mod p */
  BN_mod_exp(m1, cipher, rsa->dp, rsa->p, ctx);
  
  /* m2 = c^(dQ) mod q */
  BN_mod_exp(m2, cipher, rsa->dq, rsa->q, ctx);
  
  /* m1subm2 = (m1-m2) */
  BN_sub(m1subm2, m1, m2);
  
  /* h = qInv*(m1subm2) mod p */
  BN_mod_mul(h, rsa->qInv, m1subm2, rsa->p, ctx);
  
  /* hq = h*q */
  BN_mul(hq, h, rsa->q, ctx);
  
  /* m = m2+h*q */
  BN_add(data, m2, hq);
  
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return 0;
}

int rsa_encrypt(BIGNUM *data, BIGNUM *cipher, RSA_Params *rsa, BN_CTX *ctx = BN_CTX_new())
{
    /* Encryption: cipher = msg^e mod n */
    BN_mod_exp(cipher, data, rsa->e, rsa->n, ctx);
    BN_CTX_free(ctx);
    return 0;
}

int rsa_roundtrip(std::string msg, RSA_Params* rsa)
{
  /* Example: P: 13, Q: 17, E: 7*/
  /* Cipher: 48^7 mod 221 = 74 */
  /* Unencrypted: 74^7 mod 221 = 48 */
  BIGNUM* data = BN_new(), *cipher = BN_new();
  std::string finalOutput;
  size_t msgLength = msg.length();
  unsigned int msgPtr = 0;
  char* msgBlockData, *dataOutput;

  int maxBytes = (kBits/8)-1;

  for(int i = 0; i <= ((msgLength-1)/maxBytes); i++)
  {
    printf("\n\nPerforming operations On section [ msgPtr = %d ] [Msg Length = %d ] [ MsgLength-Ptr = %d]\n\n", msgPtr, msgLength, msgLength-msgPtr);
      
    if( (msgLength-msgPtr) >= maxBytes ){
      msgBlockData = (char*)malloc( maxBytes );
      strncpy(msgBlockData, msg.c_str() + msgPtr, (maxBytes)  );
    }
    else{
      msgBlockData = (char*)malloc( msgLength-msgPtr+1 );
      strncpy(msgBlockData, msg.c_str() + msgPtr, msgLength-msgPtr+1);
    }


    if((msgLength-msgPtr) >= maxBytes)
      BN_bin2bn((unsigned char*)msgBlockData, (maxBytes), data);
    else
      BN_bin2bn((unsigned char*)msgBlockData, strlen(msgBlockData)+1, data);

      rsa_encrypt(data, cipher, rsa);

      dataOutput = (char*)malloc( BN_num_bytes(data) );
      BN_bn2bin(data, (unsigned char*)dataOutput);
      printf("original: %s\n", dataOutput);
      printf("cipher: %s\n", BN_bn2dec(cipher));
      
      BN_clear(data);
      delete dataOutput;
      t.start();
      rsa_decrypt_without_crt(data, cipher, rsa);
      t.stop();
      dataOutput = (char*)malloc( BN_num_bytes(data) );
      BN_bn2bin(data, (unsigned char*)dataOutput);
      printf("Decrypted without CRT in %dms: %s\n", t.getElapsed(), dataOutput);
      BN_clear(data);
      delete dataOutput;

      t.start();
      rsa_decrypt_with_crt(data, cipher, rsa);
      t.stop();
      dataOutput = (char*)malloc( BN_num_bytes(data) );
      BN_bn2bin(data, (unsigned char*)dataOutput);
      printf("Decrypted with CRT in %dms: %s\n", t.getElapsed(), dataOutput);
      finalOutput.append(dataOutput);
      BN_clear(cipher);
      delete msgBlockData;
      delete dataOutput;
      msgPtr+=(maxBytes);
    }
  printf("\n\n\n\nFinal output: %s\n", finalOutput.c_str());
  printf("Comparison test: %d\n", strcmp(finalOutput.c_str(), msg.c_str()));
  BN_free(data);
  BN_free(cipher);
  return 0;
}

/* Make sure that k = (k^e)^d mod n ; for some int k where 1 < k < n-1 */
int rsa_sp800_56b_pairwise_test(RSA_Params* rsa, BN_CTX* ctx)
{
  BIGNUM* k, *tmp;
  BN_CTX_start(ctx);
  k = BN_CTX_get(ctx);
  tmp = BN_CTX_get(ctx);

  /* First set k to 2 (between 1 < n-1 ) then take ( k^e mod n )^d mod n and compare k to tmp */
  int ret = ( BN_set_word(k, 2) && BN_mod_exp(tmp, k, rsa->e, rsa->n, ctx) && BN_mod_exp(tmp, tmp, rsa->d, rsa->n, ctx) && !BN_cmp(k, tmp) );
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return ret;
}

 /*
  * Key Pair:
  * <d, n>: Form the private decryption key.
  * <e, n>: Form the public encryption key.
  * 
  * Chinese Remainder Theorem Params:        
  * <p, q, dP, dQ, qInv>: Form the quintuple private key used for decryption.
  * CRT and Euler's Theorem are used here.
  * https://www.di-mgt.com.au/crt_rsa.html
  * https://math.berkeley.edu/~charles/55/2-21.pdf
  * Benefit of using RSA-CRT over RSA is to speed up the decryption time.
  */

/* Computes d, n, dP, dQ, qInv from the prime factors and public exponent */
int gen_rsa_sp800_56b(RSA_Params* rsa, int nBits, BN_CTX* ctx)
{
  
  BIGNUM *p1, *q1, *lcm, *p1q1, *gcd;
  
  BN_CTX_start(ctx);
  p1 = BN_CTX_get(ctx);
  q1 = BN_CTX_get(ctx);
  lcm = BN_CTX_get(ctx);
  p1q1 = BN_CTX_get(ctx);
  gcd = BN_CTX_get(ctx);

  printParameter("P", rsa->p);
  printParameter("Q", rsa->q);
  printParameter("E", rsa->e);

  /* Step 1: Find the least common multiple of (p-1, q-1) */
  BN_sub(p1, rsa->p, BN_value_one());  /* p - 1 */
  BN_sub(q1, rsa->q, BN_value_one());  /* q - 1 */
  BN_mul(p1q1, p1, q1, ctx);      /* (p-1)(q-1)*/
  BN_gcd(gcd, p1, q1, ctx);       
  BN_div(lcm, NULL, p1q1, gcd, ctx);

  printParameter("GCD", gcd);
  printParameter("LCM", lcm);

  /* Step 2: d = e^(-1) mod(LCM[(p-1)(q-1)]) */
  /* Keep repeating incase the bitsize is too short */
 
  for(;;)
  {
      BN_mod_inverse(rsa->d, rsa->e, lcm, ctx);
      printParameter("D", rsa->d);
      #ifdef DO_CHECKS
        if (!(BN_num_bits(rsa->d) <= (nBits >> 1)))
          break;
      #else
        break;
      #endif
  }

  /* Step 3: n = pq */
  BN_mul(rsa->n, rsa->p, rsa->q, ctx);
  printParameter("N", rsa->n);

  t.start();
  /* Step 4: dP = d mod(p-1)*/
  BN_mod(rsa->dp, rsa->d, p1, ctx);

  /* Step 5: dQ = d mod(q-1)*/
  BN_mod(rsa->dq, rsa->d, q1, ctx);

  /* Step 6: qInv = q^(-1) mod(p) */
  BN_mod_inverse(rsa->qInv, rsa->q, rsa->p, ctx);

  printf("Took: %dms to generate CRT parameters.\n", t.getElapsed(true));

  printParameter("DP", rsa->dp);
  printParameter("DQ", rsa->dq);
  printParameter("QINV", rsa->qInv);

  if(rsa_sp800_56b_pairwise_test(rsa))
    printf("Pairwise passed!\n");
  else
    printf("Pairwise failed!\n");

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
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

