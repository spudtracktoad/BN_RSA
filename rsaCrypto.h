#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>

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
        BIGNUM encrypt(int i);
        BIGNUM decrypt(BIGNUM i);

    protected:

    private:
        BN_CTX *ctx;
        BIGNUM *p;
        BIGNUM  *q;
        BIGNUM  *n;
        BIGNUM  *e;
        BIGNUM  *d;
        BIGNUM  *phi;
        void FindD();
        BIGNUM* extGCD(BIGNUM *a, BIGNUM *b, BIGNUM *n);
        vector<BIGNUM*> extEuclid(BIGNUM *a, BIGNUM *b);
        BIGNUM* modExponent(BIGNUM *base, BIGNUM *exponent, BIGNUM *mod);
        void rsaCrypto::PrintBN(BIGNUM *val, string text)

};