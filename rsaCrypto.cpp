#include "rsaCrypto.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


rsaCrypto::rsaCrypto()
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

    BN_one(one);
    BN_set_word(e, (unsigned long) 65537);

    BN_hex2bn(&p, pChar);
    BN_hex2bn(&q, qChar);
    //n = p*q;
    if(0 == BN_mul(n, p, q, ctx))
    {
        cout << "some error with BN_mul(n, p, q, ctx)" << endl;
        ERR_print_errors_fp(stdout);
        cout << endl;
    }

    //phi = (p-1)(q-1)
    BN_sub(p1, p, one);
    BN_sub(q1, q, one);
    BN_mul(phi, p1, q1, ctx);

    p1 = GCD(phi, e);

    //phi relatively prime to 3
    if(1 != BN_is_one(p1))
    {
        cout <<"error: ";
        BN_print_fp(stdout, e);
        cout  << " is not realitivly prime to ";
        BN_print_fp(stdout, phi);
        cout << "!!" << endl;
    }

    ModInverse();

    //PrintState();
}
void rsaCrypto::PrintState()
{
    PrintBN(p, "p");
    PrintBN(q, "q");
    PrintBN(n, "n");
    PrintBN(phi, "phi");
    PrintBN(e, "e");
    PrintBN(d, "d");

}
rsaCrypto::~rsaCrypto()
{
    //dtor
}

void rsaCrypto::encrypt(string inputFileName)
{
    char input[1000000];
    BIGNUM *enInput;
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
                cout << input << endl;
                BN_dec2bn(&enInput, input);
                PrintBN(enInput, "enInput");
                //cout << input << endl;
                enInput = this->encrypt(enInput);
                //cout << enInput << endl;
                PrintBN(enInput, "enInput");
                outFile << BN_bn2dec(enInput) << endl;
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
    char deInput[100000];
    BIGNUM *input;
    //this->encrypt(inputFileName);
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
                inFile >> deInput;
                cout << deInput << endl;
                BN_dec2bn(&input, deInput);
                PrintBN(input, "enInput");
                input = this->decrypt(input);
                char *output = BN_bn2dec(input);
                cout << output << endl;
                if(!inFile.eof())
                   outFile << output << endl;
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

BIGNUM* rsaCrypto::encrypt(BIGNUM *i)
{
    return modExponent(i, this->e, this->n);
}

BIGNUM* rsaCrypto::decrypt(BIGNUM *i)
{
    return modExponent(i, this->d, this->n);
}

BIGNUM* rsaCrypto::modExponent(BIGNUM *b, BIGNUM *exp, BIGNUM *mod)
{
    BIGNUM *result = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *r = BN_new();
    BN_hex2bn(&two, "2");
    BIGNUM *exponent = BN_dup(exp);
    BIGNUM *base = BN_dup(b);
    BN_hex2bn(&result, "1");
    while(!BN_is_zero(exponent))
    {
        //if (exponent % 2 == 1)
        BN_mod(r, exponent, two, ctx);
        if(BN_is_one(r))
        {
        //    result = ((result % mod) * (base % mod)) % mod;
            //PrintBN(base, "base");
            //PrintBN(result, "result");
            BN_mod(result, result, mod, ctx);
            //PrintBN(result, "result%mod");
            BN_mod(r, base, mod, ctx);
            //PrintBN(r, "Base%mod");
            BN_mul(result, result, r, ctx);
            BN_mod(result, result, mod, ctx);
            //cout << endl << "!!!!!!!calculate the result: " << endl;

        }
        //exponent = exponent >> 1;
        BN_rshift1(exponent, exponent);
        //base = ((base % mod) * (base % mod)) % mod;
        BN_mod(base, base, mod, ctx);
        BN_mul(base, base, base, ctx);
        BN_mod(base, base, mod, ctx);
    }
    //PrintBN(result, "Result: ");
    return result;
}

BIGNUM* rsaCrypto::extGCD(BIGNUM *a, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    //base case
    if(BN_is_zero(a))
    {
        BN_set_word(x, (unsigned long) 0);
        BN_set_word(y, (unsigned long) 1);
        cout << endl;
        return BN_dup(b);
    }
    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *tmp = BN_new();
    BN_mod(tmp, b, a, ctx);
    BIGNUM *gcd = extGCD(tmp, a, x1, y1);

    //x = y1 - (b/a)*x1;
    BN_div(tmp, x, b, a, ctx);
    BN_mul(x1, tmp, x1, ctx);
    BN_sub(x, y1, tmp);
    //y = x1;
    y = x1;

    PrintBN(x, "return x");
    PrintBN(y, "return y");
    PrintBN(gcd, "return gcd");
    cout << endl;
    return gcd;
}

BIGNUM* rsaCrypto::GCD(BIGNUM *a, BIGNUM *b)
{
    BIGNUM *tmp = BN_new();
    if(BN_is_zero(b)==1)
        return a;
    BN_mod(tmp, a, b, ctx);
    return GCD(b, tmp);
}

void rsaCrypto::ModInverse()
{
    BIGNUM *a = BN_dup(e);
    BIGNUM *m = BN_dup(phi);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *zero = BN_new();
    BN_set_word(x, (unsigned long) 1);
    BN_zero(y);
    BN_zero(zero);
    BN_one(one);

    BIGNUM *q = BN_new();
    BIGNUM *t = BN_new();

    while(BN_cmp(a, one) == 1)
    {
        BN_div(q, NULL, a, m, ctx);
        t = BN_dup(m);
        BN_mod(m, a, m, ctx);
        a = BN_dup(t);
        t = BN_dup(y);

        BN_mul(q, q, y, ctx);
        BN_sub(y, x, q);
        x = BN_dup(t);
    }

    if(BN_cmp(x, zero)== -1)
        BN_add(x, x, phi);
    d = BN_dup(x);
}

void rsaCrypto::PrintBN(BIGNUM *val, string text)
{
    cout << text << ": ";
    cout << BN_bn2dec(val) << endl;
}