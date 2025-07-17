#include "../inc/cssl.hpp"
#include <openssl/bn.h>
#include <openssl/crypto.h>

int main()
{
    std::string modulus = "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb"; 
    std::string publicExponent = "010001";
    std::string privateExponent = "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1";
    std::string ex1 = "0E12BF1718E9CEF5599BA1C3882FE8046A90874EEFCE8F2CCC20E4F2741FB0A33A3848AEC9C9305FBECBD2D76819967D4671ACC6431E4037968DB37878E695C1";
    std::string ex2 = "95297B0F95A2FA67D00707D609DFD4FC05C89DAFC2EF6D6EA55BEC771EA333734D9251E79082ECDA866EFEF13C459E1A631386B7E354C899F5F112CA85D71583";
    std::string coe = "4F456C502493BDC0ED2AB756A3A6ED4D67352A697D4216E93212B127A63D5411CE6FA98D5DBEFD73263E3728142743818166ED7DD63687DD2A8CA1D2F4FBD8E1";
    std::string P =   "d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d";
    std::string Q =   "cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77";

    cSSL::RSA rsaOAEP(1024);

    // Can either load the key like this
    //rsaOAEP.loadPublicKey(modulus, publicExponent);
    //rsaOAEP.loadPrivateKey(modulus, privateExponent);

    // Additionally add and enable CRT
    //rsaOAEP.loadCRT(P, Q, ex1, ex2, coe);

    // Or generate the key using the primes
    //rsaOAEP.fromPrimes(P, Q, publicExponent);

    // Or completely generate a new key.
    rsaOAEP.generateKey();
    
    //No need to specify the label can leave it empty, same with the seed. This is mostly for ensuring a constant Encode.
    rsaOAEP.addOAEP({}, hexToBytes("18b776ea21069d69776a33e96bad48e1dda0a5ef"), DIGEST_MODE::SHA_1, DIGEST_MODE::SHA_1);

    //Leaving off the addOAEP will use raw RSA.

    auto c = rsaOAEP.encrypt(hexToBytes("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34"));
    auto d = rsaOAEP.decrypt(c);
    PRINT("Cipher: {}", c);
    PRINT("Decipher: {}", d);
    return 0;
}
