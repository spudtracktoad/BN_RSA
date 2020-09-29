#include "rsaCrypto.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


rsaCrypto::rsaCrypto(BIGNUM *primeOne, BIGNUM *primeTwo)
{
    ctx = BN_CTX_new();
    p = BN_new();
    q = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();
    BIGNUM *one = BN_new();
    phi = BN_new();
    n = BN_new();
    e = BN_new();// 65537;

    BN_set_bit(one, 0);
    BN_set_bit(e, 0);
    BN_set_bit(e, 16);

    this->p = primeOne;
    this->q = primeTwo;
    //n = p*q;
    BN_mul(n, p, q, ctx);

    //phi = (p-1)(q-1)
    BN_sub(p1, p, one);
    BN_sub(q1, q, one);
    BN_mul(phi, p1, q1, ctx);

    //phi relatively prime to 3
    BN_gcd(p1, e, phi, ctx);
    if(1 != BN_is_one(p1))
    {
        cout <<"error: " << e << " is not realitivly prime to " << phi << "!!" << endl;
    }

    this->d = this->extGCD(this->e, 1, this->phi);
}

rsaCrypto::rsaCrypto()
{
    this->n = p*q;
    this->phi = (p-1)*(q-1);
    this->FindE();
    this->FindD();
    /**cout << "p = " << this->p << endl;
    cout << "q = " << this->q << endl;
    cout << "n = " << this->n << endl;
    cout << "phi = " << this->phi << endl;
    cout << "e = " << this->e << endl;
    cout << "d = " << this->d << endl;**/
}

rsaCrypto::~rsaCrypto()
{
    //dtor
}

void rsaCrypto::encrypt(string inputFileName)
{
    int input;
    BIGNUM enInput;
    inFile.open(inputFileName);
    outFile.open("encrypted.txt");
    //cout << "encrypt" << endl;
    if(outFile.is_open())
    {
        if(inFile.is_open())
        {
            //cout << "File is open" << endl;
            do
            {
                //inFile.read(inBuffer, sizeof(int));
                inFile >> input;
                //cout << input << endl;
                enInput = this->encrypt(input);
                //cout << enInput << endl;
                outFile << enInput << endl;
            }while(!inFile.eof());
        }
        else
        {
            cout << "file not open" << endl;
        }
    }
    else
    {
        cout << "output file not open" << endl;
    }
    inFile.close();
    outFile.close();
}

void rsaCrypto::decrypt(string inputFileName)
{
    int deInput;
    BIGNUM input;
    this->encrypt(inputFileName);
    inFile.open("encrypted.txt");
    outFile.open("decrypted.txt");
    //cout << "decrypt " << endl;
    if(outFile.is_open())
    {
        if(inFile.is_open())
        {
            //cout << "File is open" << endl;
            do
            {
                //inFile.read(inBuffer, sizeof(int));
                inFile >> input;
                //cout << input << endl;
                deInput = this->decrypt(input);
                //cout << deInput << endl;
                if(!inFile.eof())
                   outFile << deInput << endl;
            }while(!inFile.eof());
        }
        else
        {
            cout << "file not open" << endl;
        }
    }
    else
    {
        cout << "output file not open" << endl;
    }
    inFile.close();
    outFile.close();
}

BIGNUM rsaCrypto::encrypt(int i)
{
    return modExponent(i, this->e, this->n);
}

BIGNUM rsaCrypto::decrypt(BIGNUM i)
{
    return modExponent(i, this->d, this->n);
}

BIGNUM rsaCrypto::modExponent(BIGNUM *base, BIGNUM *exponent, BIGNUM *mod)
{
    BIGNUM result = 1;
    while (exponent > 0)
    {
        if (exponent % 2 == 1)
            result = (result * base) % mod;
        exponent = exponent >> 1;
        base = (base * base) % mod;
    }
    return result;
}

BIGNUM* rsaCrypto::extGCD(BIGNUM *a, BIGNUM *b, BIGNUM *n)
{
    BIGNUM *tmp = BN_new();

    vector<BIGNUM*> result;
    result.push_back(BN_new());
    result.push_back(BN_new());
    result.push_back(BN_new());

    BIGNUM *x0 = BN_new(); //-1;
    BN_set_negative(x0, -1);
    result = extEuclid(a, n);
    //cout << result[0] << " " << result[1] << " " << result[2] << endl;
    BN_mod(tmp, b, result[0], ctx);
    if(BN_is_zero(tmp) == 1)
    {
        //b / result[0]
        BN_div(tmp, x0, b, result[0], ctx);
        //b / result[0]) % n 
        BN_mod(tmp, tmp, n, ctx);
        //(result[1] * (b / result[0]) % n )
        BN_mul(tmp, tmp, result[1], ctx);
        
        //x0 = ((result[1] * (b / result[0]) % n ) + n) % n;
        x0 = tmp;
    }
    return x0;
}

vector<BIGNUM*> rsaCrypto::extEuclid(BIGNUM *a, BIGNUM *b)
{
    static vector<BIGNUM*> result;
    result.push_back(BN_new());
    result.push_back(BN_new());
    result.push_back(BN_new());
    vector<BIGNUM*> internal;
    internal.push_back(BN_new());
    internal.push_back(BN_new());
    internal.push_back(BN_new());
    vector<BIGNUM*> tmp;
    tmp.push_back(BN_new());
    tmp.push_back(BN_new());
    tmp.push_back(BN_new());
    if(BN_is_zero(b) == 1)
    {
        result[0] = a;
        BN_one(result[1]);
        BN_zero(result[2]);
    //cout << a << " " << b << " " << 0 << " " << result[0] << " " << result[1] << " " << result[2] << endl;
        return result;
    }
    else
    {
        internal = extEuclid(b, a%b);
        tmp[0] = internal[0];
        tmp[1] = internal[2];
        tmp[2] = internal[1] - a/b * internal[2];
    //cout << a << " " << b << " " << a/b << " " << tmp[0] << " " << tmp[1] << " " << tmp[2] << endl;
    }

    result[0] = tmp[0];
    result[1] = tmp[1];
    result[2] = tmp[2];

    return result;
}

void rsaCrypto::PrintBN(BIGNUM *val, string text)
{
    cout << endl << text << ": ";
    BN_print_fp(stdout, val);
}