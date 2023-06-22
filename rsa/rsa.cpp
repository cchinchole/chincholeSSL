
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <chrono>


const int kBits = 2048;
int keylen;
char *pem_key;
BIO *bio_stdout;
bool doChecks = false;

struct RSA_Params {
  BIGNUM *p, *q, *e, *n, *d, *dp, *dq, *qInv;
};

int gen_rsa_sp800_56b(RSA_Params* rsa, BN_CTX* ctx, int nBits);
int rsa_roundtrip(char msg, RSA_Params* rsa);

int printParameter(const char* param_name, BIGNUM* num)
{
  BIO_printf(bio_stdout, "%-5s", param_name);
  BIO_printf(bio_stdout, "%s", BN_bn2dec(num));
  BIO_printf(bio_stdout, "\n");
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

BIGNUM* three = BN_new();
BIGNUM* five = BN_new();
BN_set_word(three, 3);
BN_set_word(five, 5);
BIGNUM* my_key_p = NULL;
BIGNUM* my_key_q = NULL;
BIGNUM* my_key_e = NULL;
BIGNUM* my_key_d = NULL;
BIGNUM* my_key_n = NULL;
BIGNUM* my_key_dp = NULL;
BIGNUM* my_key_dq = NULL;


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


BN_CTX* ctx = BN_CTX_new();
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

gen_rsa_sp800_56b(rsaPtr, ctx, kBits);
rsa_roundtrip('0', rsaPtr);

BN_clear(three);
BN_clear(five);
BN_clear(my_key_p);
BN_clear(my_key_q);
BN_clear(my_key_e);
BN_clear(my_key_d);
BN_clear(my_key_n);
BN_clear(my_key_dp);
BN_clear(my_key_dq);
BIO_free_all(bio_stdout);
BIO_free_all(bio);
free(ctx);
free(pKey);
free(pem_key);
return 0;
}



int rsa_decrypt_without_crt(BIGNUM* data, BIGNUM* cipher, RSA_Params* rsa)
{
  /* Decryption: msg = cipher^d mod n */
  BN_mod_exp(data, cipher, rsa->d, rsa->n, BN_CTX_new());
  return 0;
}

int rsa_decrypt_with_crt(BIGNUM* data, BIGNUM* cipher, RSA_Params* rsa)
{
  /* Using CRT for decryption */
  BN_CTX* ctx = BN_CTX_new();
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
  
  BN_clear(m1);
  BN_clear(m2);
  BN_clear(h);
  BN_clear(m1subm2);
  BN_clear(hq);
  BN_CTX_end(ctx);
  return 0;
}

int rsa_encrypt(BIGNUM* data, BIGNUM* cipher, RSA_Params* rsa)
{
    /* Encryption: cipher = msg^e mod n */
    BN_mod_exp(cipher, data, rsa->e, rsa->n, BN_CTX_new());
    return 0;
}

int rsa_roundtrip(char msg, RSA_Params* rsa)
{

  BIGNUM* data = BN_new();
  BIGNUM* cipher = BN_new();
  BN_set_word(data, msg);
  printf("original: %s\n", BN_bn2dec(data));

 
  rsa_encrypt(data, cipher, rsa);
  printf("cipher: %s\n", BN_bn2dec(cipher));
  BN_clear(data);

  auto start = std::chrono::high_resolution_clock::now();
  rsa_decrypt_without_crt(data, cipher, rsa);
  auto stop = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
 
  printf("Decrypted without CRT in %dms: %s\n", duration.count(), BN_bn2dec(data));
  BN_clear(data);

  start = std::chrono::high_resolution_clock::now();
  rsa_decrypt_with_crt(data, cipher, rsa);
  stop = std::chrono::high_resolution_clock::now();
  duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
  
  printf("Decrypted with CRT in %dms: %s\n", duration.count(), BN_bn2dec(data));


  /* Example: P: 13, Q: 17, E: 7*/
  /* Cipher: 48^7 mod 221 = 74 */
  /* Unencrypted: 74^7 mod 221 = 48 */
  return 0;

}

/* Computes d, n, dP, dQ, qInv from the prime factors and public exponent */
int gen_rsa_sp800_56b(RSA_Params* rsa, BN_CTX* ctx, int nBits)
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
     if (!(BN_num_bits(rsa->d) <= (nBits >> 1)) || !doChecks)
      break;
  }

  /* Step 3: n = pq */
  BN_mul(rsa->n, rsa->p, rsa->q, ctx);
  printParameter("N", rsa->n);

  /* Step 4: dP = d mod(p-1)*/
  BN_mod(rsa->dp, rsa->d, p1, ctx);
  printParameter("DP", rsa->dp);

  /* Step 5: dQ = d mod(q-1)*/
  BN_mod(rsa->dq, rsa->d, q1, ctx);
  printParameter("DQ", rsa->dq);

  /* Step 6: qInv = q^(-1) mod(p) */
  BN_mod_inverse(rsa->qInv, rsa->q, rsa->p, ctx);
  printParameter("Qinv", rsa->qInv);

  /*
   * Key Pair:
   * <d, n>: Form the private decryption key.
   * <e, n>: Form the public encryption key.
   * 
   * Chinese Remainder Theorem Params:        
   * <p, q, dP, dQ, qInv>: Form the quintuple private key used for decryption.
   * CRT and Euler's Theorem are used here.
   * https://www.di-mgt.com.au/crt_rsa.html
   * Benefit of using RSA-CRT over RSA is to speed up the decryption time.
   */


  BN_clear(p1);
  BN_clear(q1);
  BN_clear(lcm);
  BN_clear(p1q1);
  BN_clear(gcd);
  BN_CTX_end(ctx);
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

