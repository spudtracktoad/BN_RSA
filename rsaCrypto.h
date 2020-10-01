#include <iostream>
#include <fstream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

class rsaCrypto
{
    public:
        rsaCrypto(BIGNUM *primeOne, BIGNUM *primeTwo);
        rsaCrypto(unsigned char *primeOne, unsigned char *primeTwo);
        rsaCrypto();
        virtual ~rsaCrypto();
        void encrypt(string inputFileName);
        void decrypt(string inputFileName);
        BIGNUM* encrypt(BIGNUM *i);
        BIGNUM* decrypt(BIGNUM *i);

    protected:

    private:
    char *pChar = "E32308A637427EDD93D2AD553F5A64C158A952605261F8E6324F269542260643179CE1BE8BD469BAFBD17FA128C109759F8A914E0E3F65DB3656239812ED8723";
    char *qChar = "C8D4677D08D8A6BC181869316DC156C6E53C03F7E106DF3547619FFB61AFFB189E2C79512FEAD83F6A228CC23AF4F8DFFB45287A5F8482B56DD8B6CE0887504F";

    //unsigned char pChar[64] = {0xE3, 0x23, 0x08, 0xA6, 0x37, 0x42, 0x7E, 0xDD, 0x93,
    //0xD2, 0xAD, 0x55, 0x3F, 0x5A, 0x64, 0xC1, 0x58, 0xA9, 0x52, 0x60, 0x52, 0x61, 0xF8,
    //0xE6, 0x32, 0x4F, 0x26, 0x95, 0x42, 0x26, 0x06, 0x43, 0x17, 0x9C, 0xE1, 0xBE, 0x8B, 
    //0xD4, 0x69, 0xBA, 0xFB, 0xD1, 0x7F, 0xA1, 0x28, 0xC1, 0x09, 0x75, 0x9F, 0x8A, 0x91, 
    //0x4E, 0x0E, 0x3F, 0x65, 0xDB, 0x36, 0x56, 0x23, 0x98, 0x12, 0xED, 0x87, 0x23};
    //unsigned char qChar[64] = {0xC8, 0xD4, 0x67, 0x7D, 0x08, 0xD8, 0xA6, 0xBC, 0x18,
    //0x18, 0x69, 0x31, 0x6D, 0xC1, 0x56, 0xC6, 0xE5, 0x3C, 0x03, 0xF7, 0xE1, 0x06, 0xDF,
    //0x35, 0x47, 0x61, 0x9F, 0xFB, 0x61, 0xAF, 0xFB, 0x18, 0x9E, 0x2C, 0x79, 0x51, 0x2F,
    //0xEA, 0xD8, 0x3F, 0x6A, 0x22, 0x8C, 0xC2, 0x3A, 0xF4, 0xF8, 0xDF, 0xFB, 0x45, 0x28, 
    //0x7A, 0x5F, 0x84, 0x82, 0xB5, 0x6D, 0xD8, 0xB6, 0xCE, 0x08, 0x87, 0x50, 0x4F};
        BN_CTX *ctx;
        BIGNUM *p;
        BIGNUM *q;
        BIGNUM *n;
        BIGNUM *e;
        BIGNUM *d;
        BIGNUM *phi;
        BIGNUM *x, *y;
        ofstream outFile;
        ifstream inFile;
        BIGNUM* GCD(BIGNUM *a, BIGNUM *b);
        BIGNUM* extGCD(BIGNUM *a, BIGNUM *m, BIGNUM *x, BIGNUM *y);
        //vector<BIGNUM*> extEuclid(BIGNUM *a, BIGNUM *b);
        BIGNUM* modExponent(BIGNUM *base, BIGNUM *exponent, BIGNUM *mod);
        void PrintBN(BIGNUM *val, string text);
        void PrintState();
        void ModInverse();
};