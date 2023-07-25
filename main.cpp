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
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <openssl/rand.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "inc/defs.hpp"
#include "inc/utils/logger.hpp"
#include "inc/crypto/rsa.hpp"
#include "inc/math/primes.hpp"
#include "inc/math/rand.hpp"
#include "inc/hash/sha.hpp"
#include "inc/tests/test.hpp"
#include "inc/hash/hmac.hpp"
#include "inc/crypto/ec.hpp"
#include "inc/utils/time.hpp"

const int kBits = 2048;
int keylen;
char *pem_key;

uint8_t *scanHex(char *str, int bytes) {
    uint8_t *ret = (uint8_t*)malloc(bytes);
    memset(ret, 0, bytes);

    for (int i = 0, i2 = 0; i < bytes; i++, i2 += 2) {
        // get value
        for (int j = 0; j < 2; j++) {
            ret[i] <<= 4;
            uint8_t c = str[i2 + j];
            if (c >= '0' && c <= '9') {
                ret[i] += c - '0';
            }
            else if (c >= 'a' && c <= 'f') {
                ret[i] += c - 'a' + 10;
            }
            else if (c >= 'A' && c <= 'F') {
                ret[i] += c - 'A' + 10;
            }
            else {
                free(ret);
                return NULL;
            }
        }
    }

    return ret;
}

//perform the SHA3-512 hash using OpenSSL
char *sha3_512(char *input, size_t input_len)
{
    uint32_t digest_length = SHA512_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_512();
    uint8_t* digest = static_cast<uint8_t*>(OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, nullptr);
    EVP_DigestUpdate(context, input, input_len);
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    char* output = (char*)byteArrToHexArr( (unsigned char*)digest, digest_length);
    OPENSSL_free(digest);
    return output;
}


int main(int argc, char *argv[]) {
  BIGNUM* myE = BN_new();
  BN_set_word(myE, 0x100000001);

  /* Set the OPENSSL Rng to use our own method. */
  /* This is deprecated needs updated */
 // RAND_set_rand_method(RAND_stdlib());

  /* Make a syscall to /dev/urandom for 4 bytes that can be used to seed the prng */
  unsigned char buff[4];
  syscall(SYS_getrandom, buff, 4, GRND_NONBLOCK);

  //RAND_seed(&buff, sizeof(buff));

  cRSAKey *myRsa = new cRSAKey(kBits, myE, true);


  BIGNUM *bnLongRand = BN_secure_new();
  BN_rand_ex(bnLongRand, 1024, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, BN_CTX_secure_new());
  unsigned char* testBytes = (unsigned char*)malloc(32*sizeof(char));
  RAND_bytes(testBytes, 32);
  roundTrip(myRsa, (char*)"Test string HeRe! HelLO WoRLd!@#$^&*()_+ 1   2 34    567  89\nTest!");
  printf("\n\nTesting long string now.\n\n");
  roundTrip(myRsa, (char*)BN_bn2dec(bnLongRand));

  testSHA( (char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" , strlen("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), (char*)"84983E441C3BD26EBAAE4AA1F95129E5E54670F1", SHA_1);
  testSHA( (char*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", strlen((char*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
  (char*)"09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039", SHA_384);
  testSHA((char*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", strlen((char*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
  (char*)"8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909", SHA_512);
  testHMAC( (char*)scanHex( (char*)"4869205468657265", 8) , 8, (char*)scanHex((char*)"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 20) , 20, (char*)"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", SHA_512);
  testHMAC( (char*)scanHex((char*)"4869205468657265", 8) , 8, (char*)scanHex((char*)"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 20) , 20, (char*)"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6", SHA_384);
  testHMAC( (char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", strlen((char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), (char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", strlen("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), (char*)"78e2e78c51a4b45a95536c4a1fa2bf72cfbd8f0b", SHA_1);
  testSHA((char*)scanHex((char*)"36", 1), 1, (char*)"c1dfd96eea8cc2b62785275bca38ac261256e278", SHA_1);
  testSHA( (char*)scanHex((char*)"195a", 2), 2, (char*)"0a1c2d555bbe431ad6288af5a54f93e0449c9232", SHA_1); 
  testSHA( (char*)scanHex((char*)"45927e32ddf801caf35e18e7b5078b7f5435278212ec6bb99df884f49b327c6486feae46ba187dc1cc9145121e1492e6b06e9007394dc33b7748f86ac3207cfe", 64), 64, (char*)"a70cfbfe7563dd0e665c7c6715a96a8d756950c0", SHA_1); 
  testSHA((char*)scanHex((char*)"57e89659d878f360af6de45a9a5e372ef40c384988e82640a3d5e4b76d2ef181780b9a099ac06ef0f8a7f3f764209720", 384/8), 384/8, (char*)"f652f3b1549f16710c7402895911e2b86a9b2aee", SHA_1);
  testSHA((char*)scanHex((char*)"7c9c67323a1df1adbfe5ceb415eaef0155ece2820f4d50c1ec22cba4928ac656c83fe585db6a78ce40bc42757aba7e5a3f582428d6ca68d0c3978336a6efb729613e8d9979016204bfd921322fdd5222183554447de5e6e9bbe6edf76d7b71e18dc2e8d6dc89b7398364f652fafc734329aafa3dcd45d4f31e388e4fafd7fc6495f37ca5cbab7f54d586463da4bfeaa3bae09f7b8e9239d832b4f0a733aa609cc1f8d4",
    1304/8), 1304/8, (char*)"d8fd6a91ef3b6ced05b98358a99107c1fac8c807", SHA_1);
  testSHA((char*)scanHex((char*)"6cb70d19c096200f9249d2dbc04299b0085eb068257560be3a307dbd741a3378ebfa03fcca610883b07f7fea563a866571822472dade8a0bec4b98202d47a344312976a7bcb3964427eacb5b0525db22066599b81be41e5adaf157d925fac04b06eb6e01deb753babf33be16162b214e8db017212fafa512cdc8c0d0a15c10f632e8f4f47792c64d3f026004d173df50cf0aa7976066a79a8d78deeeec951dab7cc90f68d16f786671feba0b7d269d92941c4f02f432aa5ce2aab6194dcc6fd3ae36c8433274ef6b1bd0d314636be47ba38d1948343a38bf9406523a0b2a8cd78ed6266ee3c9b5c60620b308cc6b3a73c6060d5268a7d82b6a33b93a6fd6fe1de55231d12c97",
   2096/8), 2096/8, (char*)"4a75a406f4de5f9e1132069d66717fc424376388", SHA_1);
  testSHA((char*)scanHex((char*)"9b5f37f5dcedd96d9b7ff6d852b77ef90498311d24dfa906b2979b28a7e85a1893309c41855581d92b59d1133a2e859610cc8a2f9982c1c26f894a8745df027285524af338db0be0272ef7b03f8f11e93ae76fdb7c173e8f3b8c08fbe3143277b9f0c975be2a7e6cd629ee15298227daca11688c9749295460c85bec4b2ef10e76309f2ddfe8e264816f40acc0aed1510771fea7b0bd89f92464cec243d6481f063a568562be3faf702b74dbccbc16363b30b895901e6665d089e6e594b43d93af3776e311539e37eb83130c1453ff71ac751fbeff12c982ab5e2dbd066fdb50ba4f85b1b25006e33a9fa4a6611c92eba269b98ac441b937ff0c2ab360b0273f6fa90d560e5c809ba4a8af117bbfd98a67341162a9553e6c12ba652d6c1e2b48156e953aed20134772c6bdb42ae3dc3742fdacac74f360092e916794f062ee54f5c5a6c51743c7d0ed2055f93630a2db7aec14d1eec528f799b9b751b523784958d7c75f536ea41c5adfff476650335c582bd03adf739d1c9b59ddca830ad21184cc80706a49b314042a430783e897a424df684e0fa5c7617e99626921bf0392c2cb5960257bfba0322aaa9f55a3d699263364744502afae88a2cd9559e913b659fcdb974aad84a92b07bb78a426f925a54d4d164b325cec039ca6b5f1300b6393888d7ea186571538e8fffa381c082feb55ab9be7ded60135af7633b23ef283b697f77bf4af7bcea1f5fc8dd92b099e3e74046be2ae26d76701c37664b8d0fd0b50a2f709cff8baae583c9a4efb065ce7d1e2ee03495355e0bd18e6cf49adb9dadc155ba98fd7c3a7364787603506502d96cc8c14586562ea09faebba97929f6b63d80d9c971fd0d3baa3bed78112625ae84baddb8265e8cb0df3edef4a8697050c7477aa8ed8c87b09daa57b86317ab5f1e6b922705aceccf38a54340b9289f1ff70ff9b1d0b95e74e74a613ed6b8085d92518afc94cfc35e048885282bd5d7865540f36ebbf1e5faff728695dc85c13c890324a3644594efeb3f111560ffbe066a90e44a1fc4b2b54ed93437f51f7a7e5b06fbd5f48cf5e7555f8382f904b7129f6648de6ca049266dd4e6afb0d3788580c38cfeb6345af6db60391b7493675d7c378d9633231dd0d50c3a6780505004a2cf347839aa4870d5c7ce29341a2329799b4f0bf3bba5570cd59be9e3f4a55e3990aeecef7d22f7dd1c9f46e8079f192fe7f9aa3ee873fb8dc787c17c5ecd04adae38c7581b8efe69d548fee0fa1faef7d419eb75181e60c0588a6889fd5b9a877e8e91f403e0e7046837abbf50495d79b63c5a26f8e9195d1f1059cd3eb5824f97fcc753d4dd64256c07f7e3a880a72e24bd70d4d97877bc71c61f96b18f4e7e712fe1e7fcb8d85557264dfe717a0e7d9629c9ff58511e5706f82476e42d718c90848c30ea27c60c900f2850398a15f0810db016e3e77fb52532f2fe55347e028c9700cf3b8ebfc3cd4f11996f25301f8be5edac0ac01e7f7313258d7328d678abd3ea035f7228035552942a90ffff630d2ebd3f4b6f7cee76f516c4cc7f1d47a4c7c28dc4568153deb62a942d6ec6538b64b941043a0dba87755104dfaba4f7ddef04bf18c07e3dbfe63f66c2f647799d046c41f3d4533c4af05eee0b332021ddb63b27bb3451197f6f5d02c02ad54da8aa30b268b2e01c3812bae10da9f13e1ab9e0582a26bc8f93ce0df8c371023834b2c132f15a36b2b548df8e2574aaa51b666eb0f41c02f8a36eccc93b7d50d1d7aa78141c3ec99868ff57260127bf0f664860c28788e6fd14de03f496844392f81dd00657d50b45b9c29c791f47a0c571ec411d82f1baf56e986dfb733a5cf41c79636a22b18e433e2f19d7de38e27fd4aeaa2244eb118a273a455e4003ff9dbb499cb00b58d5095c9179d2dc800696e52be6616bd96d23c510348d9b85bdd86b0b0688703f42109b9616ea88c18f9349c0906b5641204aced6b619c4141a3c923a1b540fd987e171a99b8f6151e00d7929229092b6fd67baea448378539742d753559328cc09048548525204d5aa5dd9a23781bfbf37130fb75a4b16b8b78390e34fd6596b37f23cfee5b2d1b1411d01e829bf2bae8fd533ea71e13da7ed675576648e204ba7231f49b022566936b37857839965294a16dde025d64bc5bb769b693e3b0bf1d91f82956c3111820dc9b37cdfa10a9408605434e0aacf86a429e948275d7ae240502d7e546f818038c839c498867a933d4a3d553ccf476f3a09b5afca760b817f6d7671132e24e84a2771cb488a339b7b2cffcd94c431e3ef8e86ec92152c73d8bfd3fa22fd7a2eb47ff1fd5a5cd4012481220a731a1d893730e3ab18ab5c2dfedfec960e7e0fc7fa2a40d7585eca88dbff3a98624168c393994247c8a92904544626c13ff044489dced4e5cd00858703ffbff3ecdab2279710296f1cbf01bb7b7af8f82224c62511c634a522f2a3803efb08a97d367829b43e1f7d9f2d74a7d6e6f9c76f6be3e1f8b8c691f4958308ef89cb259df5394e7d8b7affcaa4f05de9229fab72365c13b51f3148ac89c28588247e04b987541a4580f2622996134234b66110d5246d1ec951db15d51fe08aab4387a36a7d76f1ceb6ec3136714c095c0ad49402b6b577c7f94aa5e8f85b8ccb6f7eae2b3810795b75ef096bd718f791a860a1755db3c3138df655627392006b10c96176579f258e7661575437e8a1a8079bc5b799e6654e8864c0cc42229a0cd00e89d65c916ada10f9876a04599bf1b0fc7d43ebdbf2cb611c54a0c49b9e13159463b5a795ddb0ddfe2627ccea5af13cf934a4d3f2e03cb093ad6a7b5b91206a21abbec8fae2c55605b00811f94338f4288854d2c9a1f4ff612793e6e127b7360cbe3c415f0e69e1a6b1a55425093b7ee0f4ce78cedc9695eb5fb797daa64a11dc17c8a120d5213947b76a03fbf17b45d8e69c3680e4941cb8b24ffe96b15b760644de68fecb8d956f1de0b1ccb07ae176fa288c7e5e700c4fcbc79ba3cd5deb21c207e9375601be837173de35baacca218c0deb25aebced2708a8ef904ee3e9a51bbfd269091ffd3b3ecdf9c56493788f38b6f30559cd27b4f57e7adada6fea06be709502595ad9ecf24994da62c175166cae049be44354a01eb2bde1e46474cd26c4a1a1cb24ed1f2861200329b9383db47dc057d291ec4ee0e03943f154027ee126a8b5d310af483dcf3bce2ded3a8b9c8096d7a93b6737e8817d8f85d12b828a10eacd15a0890ecece38a9e3c004768160f889ecc25de1a200eb13164e487e6e0e0835e74712c947f8b714eff42e950f9975fcf1b928d28a09128d274df1d9198881bedc96c51e35c9379da6dc015d93849f8f6c7250912ce4744c3d32a019291ae79679f2286414da2aa2acfa3536b9dcc5dfc1908d93e72d90decc9efbb4f93f9a7b23fbb531618600d276c122b6eeec996c75960851656ee8b36a053d4326611acb8f15e40ca8677a9b78e36264af4e7a941cf589600412fc7879e80d3a2d19f905ffc33d6c55f8c86c37b37cb6777cfa051c2159366fa43c8c90d9e40079e4b5b91aa639c706b4aad347c3ca32d3f2882de7cc204af4ad496e233d4a4c893bc163541161b31715625f0d96d3505139b58d243857143f9873abc594b864f799bc9330a73d9713b5bf6e1daf30955bcd029146086638acf06bb3dc62b6e03178f7a734da360998fff29eec7f6a786036efd8c1bee62ec94f9214fc49be44c374133dc52ce380f36eac5fee79d9801ae1edd22bbe5f4d10f0775d999c371929f58fb58601ae73df8c5d2fb8311632d8587cfbe8a92a3a109d9bec28ecc9c3d187ddbcfc0b2f7899c3859cce37a90715252de48ce1ef6c44a1704f4ebdeeeb56a58d927bbbcf05decea60594fffa737db260fa8d0b175a29a684f56f820ee635d90004997615820ae84f28a0fc831e6e9ac6cc6d871a9a3c174a8d0fdbb24adb9ce551d9cc8b93aabad14476afeb6e5448bfc8a2d89193086e4164a41d718fc45b9e28b141a9a13ab0ed078aac9bc9eb46cc7dd191f4eafb260a2ac0d9a53b9cafaae7c457e8413764f2d051550cd7801f7d6a5e25cce8a0d8f53dea92f5c4a1038c1d6781dfea2d31734d6f4bc70dbf2d330ccd16723275f1a31c95dbcbb19df1c2483f61e90288b0eebd38e342e2f51a9dd382e69d4f070a84453716af98cff4ede6904aac20d66dd5ce52de18ddde420e6d341896a4b08e295652c609d0d3775f772ede91db92c2c8ff217eb174b74e1528351f06ca2ee702be8d7c72f0351397885f7022894a5a28ae3957954e2c8932932a8c5625cebf90ec2bac637d6134468896c1e6b0799e857a1efb3cb0aaadf74c78c31d5e1c72547dd1d863eed463bcf6892646f78cfa6fe136dc2042ce06d3a2a465c4c994a9edd1f482ecbb2b2c9b509b2fdbb501083852057ce87ae33e483431e6d4fec3b09d87282e7678c1e9423541310d8f82427f6b2f4feddfa6bed57fa5b8c6642641141bd15d999e353442031ffc64cd6d33b58b08d7b8d76502fbf3747e31a038b5c1fe8472be9201a82b588bc47a154e567b4016a6d1f8ca953c2e22897f29779927ada6106dfa939f6e94193ba5ed92152118fd3fb1ba3400069e347d37766f65c5a7daa9104e77847c444cc470ccc50a57741104d0a22dbdfbb22ecbd2fd9ca62c8b86cf5df42a11d4e79af1832973a07efff688c74734397c0875f7da456bc4bcb73ed59f9237a2290c9845258a1a7217fb125e0dffd40d180fbe73c5e4695bf6c9677e6d8f0cdfc911a922007525f9b323f8d70d5289a350464cd22e4121d68b20a50c306136053595622a8c512291c0d92e965dd5c186a53ac5a56bd201ceba5b5c01a0bf2fbd0f1637c121d49cf4c1a9080e68001831975b9d30174da5af34d8011106df7681a602be887945f17d460229c1c447fa3e97375834a8ea79e26b35389cfb6886edaae94ae2fb4bcca5ce731832fb43f408354c6b15a95eeb22cde17727f6d0fd4b8e488153104c9b08bb8a37e4655a7228e2096a45811195caed6b212471bf3635b09ee66b50cec900ada62d589b12010b3dfcca56d888f6554a40eb250479ce36c25adeae5558e33805554d0214f13d49a9a50fcc184b895c54f1299c279721c9241afe6e7661862963263b736b7e634ea590af17b8cfcb3aadfa511c43addd57663dba5e3c7f0e3f47876d1ef7203f94c22e2ccc429c389aa5db1607e1045d8c096196e0201807e412f74677507d0eb67ffc0d4c3e175dd6ed01dcf198612eb17df51886b9b2ffd265f47c1f0feb7d1e4f78c52a13f7a789d40d1a6bd21acd723486b3c481d64264a11d62787e01e746a122e8e85c83a22e0b5b42d916b7b638dd850d2be1089c3564d09e162336f9da2598ed098061ea2df38b0acbeebe859fd97e692f7fb059af119c836aa82111233d3946001808cc241d0ac6a6b29597f1a8e16c31b664074c47ffb7087526c9cc7892985e9beed48af8691b0c1ae379f8dc4c9af51d9a21876868ad5202de802038133897849aafdd06145c6e801eb7ffd41e59cc2dd9350b0365dae9e9aed0e91c59bb2d5a829a94d69b1f407aadbe8130e53d396f97be21a985d422822e386195d4a492963d414cda6bd82473271a17732fc9cf4b6c2975bb370dbe74b3233424f27959b031205f92152b7cf201474d0b5c73e049bd0371c907fbf03a042ddb5a519e0540f4a4679e156dcc8fc2b27c7a09b03f0300d8a04357337a3a67c4b1a670a707c0fe69df4eeb339594f208303fa6231ddfde257bcac328befe74647189be18f3a8b4dd312514f16ab9f5a502dcb0311f58bb568ebfda60310ea0997574b8683b60ce7b07c1114bbe5774156ec1c66eb6061ef833a2eb5e72e372e04807ee09419191cfbda36e86f305c3d5ce9f473074607f9715149497e70571b563b3dd90c8b3b547ed3c9b57cb4d8b62ccb5b12acce0639fad7554911ffd13a552f8f583133f9f7ff10d062289872148c3b592b2420e519e5755b9de8032df2c9057c464d3adb6d473956d7bc05b3bf45e1f7a6b5652c00fcd2622d4ba3f4aa79640c89a6c7691e1ef560fc7f2221201f643c6ba8c56456059772e18207adcc2ef5480a84032c734becf8b9bb18469de16d316245671482c96b93a1d458e0bfb06037b13116abd298c725f6b60eaa9f55a3dc74d374c4ee10f7ce558bbe15ebc74ce167f4276ea4cb2ef09bba2dd38f41af47879c13fc01a2e22ae5ed60d5b83b614f12145efe52adc85f900d9c4bd36e387a84e66d452346d5b0394367a78ed348889bdae4e242063e7dbdf7849ad5a4e77b54faaa26bcc6786739d4fa14d558a994eb8ee1a2de9e374f0ac20d46fbaa6454dd20f12834e87257ceea42a3f5932b7ce9787cc78d3c5cdf60b45ed9af4a560d099f6ad1f4756c88decb67dc564977477cdfded8b6aa5534a517a0db584a65acbfc13eac62340d0352c09047604535fd8e0d2f5dc3aec956c331fad25d733a3be7cc953ee7effecf1311e56d7c4e0ca7064896df1b11614ea04b9548288d7dc168099611ec6ce6f408068fd5102ba44ccbd93be5269ac42326ac99c42060d6472cc06aacd7746e7b18e7b60786a5a6f4c70847f74c139add3b9e2dcfadb3ebd41a39389711cf3e6b2dfb818c4484baa7e11ce29df5428d85c96779f0375067701abb295b0345fdcc2e8b19ebb490876e015f336089f14321b750a6af26fdf023148f657f149e53a602dfa6ac3c90b6500f1763c770e664bceda1dc94e3832ef6f0fe138baba1ea02933f4f58464eee56f48d995b12ea995b53a24228d4aacbf0964e5c07321867e7c8f33c763990d8879609fea2d8c48a08d19b01f262396c1aefc7677c10c9755e8942968e7d1f1cebded2ba26283edeca4fd3407af5fabb7ae1b35d72ad7cba6ebe7685287ac3618ab432f46f6b1e3daab5932849f6b3601b5558656f71fbde1f4fd530cd98434f6d016fd5030a2d51aeeb23e1e6cb2d03023400a8fdc40d8a7925a8c0043f698f9babd2846c6b33bfe0d9cb92d9de304b3964f14da30e79668526365c56d7fbc91c9ca32932f8f8324868d364ab9684e0c7cf737deab708194a3bc92d4ac8c2a4f9ba2aeedb184350ed7e827ee35af06bb45bd0605827824cd04da75b687a86c939efaff9f132ddc1d704210809943d9408f24e1d77c6afa62042190d38550fe0e4227972fcb08f2e0ee3f82ca6ab3302cc7b37ddcffd56d04104676b43c22490033bd18282f91f3f9b014f1041079a5e08ded1c7e63241713b79d99e10278f819c21ff510d75559b85486edc62103a4fc203650446ce3632178bb7ce27ed165cbabe4b06248cfbebd49f9cb9912edb7e04d23abb773afebbdc214822117d82c962f9fcc950a6d7d690ed23cf57c94492d5339a15ffdd61b39222d5c3553d9a6f9eba5cc4172bb305c21c49453b493e343e0ecb3a681e26c24278a6d97b9728f775e9b11c0483551f72135743c616910c454b16513a671791f30a038b0cf2f208f06f44fc9c1685cda6ba94f37e9805c1f5d2c382fb1ffac8adc034018fb6c24b15325d8a694d0db768f94a7bed3761fc538b1af735ad980f788280648c4a5e68ee1b44eef28eb484bfb8bf039b5c6f64695e63d5",
   43280/8), 43280/8, (char*)"ed76c5bf4ada6a2092e6dbb40ff40909b8ec06cb", SHA_1);
  testSHA((char*)scanHex((char*)"63bfc1ed7f78ab",
   56/8), 56/8, (char*)"860328d80509500c1783169ebf0ba0c4b94da5e5", SHA_1);
   
  testSHA( (char*)"abc", strlen((char*)"abc"), (char*)"e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", SHA_3_224);
  testSHA( (char*)"abc", strlen((char*)"abc"), (char*)"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", SHA_3_256);
  testSHA( (char*)"abc", strlen((char*)"abc"), (char*)"ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25", SHA_3_384);
  testSHA( (char*)"abc", strlen((char*)"abc"), (char*)"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", SHA_3_512);
  /* Small test to make sure all my SHA_3 lines up with openssl's */

  
  
  int failed = 0, passed = 0;


  SHATestCase *failedCases[50];

  int osslTime = 0;
  int myTime = 0;
  
  for(int i = 1000; i < 55000; i++)
  {
    unsigned char buff[i];
    syscall(SYS_getrandom, buff, i, GRND_NONBLOCK);
    Timer t;

    t.start();
    SHA_Context *ctx = SHA_Context_new(SHA_MODE(SHA_512));
    unsigned char rawDigest[getSHAReturnLengthByMode(ctx->mode)];
    sha_update( (uint8_t*)buff, i, ctx);
    sha_digest(rawDigest, ctx);
    unsigned char *hexStringMINE = byteArrToHexArr(rawDigest, getSHAReturnLengthByMode(ctx->mode));
    t.stop();
    myTime = t.getElapsed();


    t.start();
    unsigned char osslHash[getSHAReturnLengthByMode(ctx->mode)];
    SHA512( (unsigned char*)buff, i, osslHash);
    unsigned char *hexStringOSSL = byteArrToHexArr(osslHash, getSHAReturnLengthByMode(ctx->mode));
    t.stop();
    osslTime = t.getElapsed();




    printf("Test [ %d ]: Time difference from mine to ossl %dms\n", i, myTime - osslTime);


    if(strcasecmp((char*)hexStringMINE, (char*)hexStringOSSL) != 0)
    {
        failedCases[failed++] = new SHATestCase(i, 512, (uint8_t*)byteArrToHexArr(buff, i), (uint8_t*)hexStringOSSL, (uint8_t*)hexStringMINE);
    }
    else
        passed++;
  }
  printf("%dms is my average time\n", myTime );
  printf("%dms is ossl average time\n", osslTime );
  printf("%d test cases passed\n", passed);
  printf("%d test cases failed\n", failed);
  for(int i = 0; i < failed; i++)
  {
    
    SHATestCase *c = failedCases[i];
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("Case Number: %d\n", c->data_len);
    printf("Original Data: %s\n", c->msg_bytes);
    printf("My       Data: %s\n", c->TEST_hash);
    printf("KAT      Data: %s\n", c->KAT_hash);
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
  }
  
  return 0;
}