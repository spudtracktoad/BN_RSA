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

    BN_set_bit(one, 0);
    BN_set_bit(e, 0);
    BN_set_bit(e, 16);

    BN_hex2bn(&p, pChar);
    BN_hex2bn(&q, qChar);
    PrintBN(p, "p");
    PrintBN(q, "q");
    //n = p*q;
    if(0 == BN_mul(n, p, q, ctx))
    {
        cout << "some error with BN_mul(n, p, q, ctx)" << endl;
        ERR_print_errors_fp(stdout);
        cout << endl;
    }
    PrintBN(n, "n");

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

    PrintState();
}
void rsaCrypto::PrintState()
{
    PrintBN(p, "p");
    cout << endl;
    PrintBN(q, "q");
    cout << endl;
    PrintBN(n, "n");
    cout << endl;
    PrintBN(phi, "phi");
    cout << endl;
    PrintBN(e, "e");
    cout << endl;
    PrintBN(d, "d");
    cout << endl;

}
rsaCrypto::~rsaCrypto()
{
    //dtor
}

//void rsaCrypto::encrypt(string inputFileName)
//{
//    int input;
//    BIGNUM enInput;
//    inFile.open(inputFileName);
//    outFile.open("encrypted.txt");
//    //cout << "encrypt" << endl;
//    if(outFile.is_open())
//    {
//        if(inFile.is_open())
//        {
//            //cout << "File is open" << endl;
//            do
//            {
//                //inFile.read(inBuffer, sizeof(int));
//                inFile >> input;
//                //cout << input << endl;
//                enInput = this->encrypt(input);
//                //cout << enInput << endl;
//                outFile << enInput << endl;
//            }while(!inFile.eof());
//        }
//        else
//        {
//            cout << "file not open" << endl;
//        }
//    }
//    else
//    {
//        cout << "output file not open" << endl;
//    }
//    inFile.close();
//    outFile.close();
//}
//
//void rsaCrypto::decrypt(string inputFileName)
//{
//    int deInput;
//    BIGNUM input;
//    this->encrypt(inputFileName);
//    inFile.open("encrypted.txt");
//    outFile.open("decrypted.txt");
//    //cout << "decrypt " << endl;
//    if(outFile.is_open())
//    {
//        if(inFile.is_open())
//        {
//            //cout << "File is open" << endl;
//            do
//            {
//                //inFile.read(inBuffer, sizeof(int));
//                inFile >> input;
//                //cout << input << endl;
//                deInput = this->decrypt(input);
//                //cout << deInput << endl;
//                if(!inFile.eof())
//                   outFile << deInput << endl;
//            }while(!inFile.eof());
//        }
//        else
//        {
//            cout << "file not open" << endl;
//        }
//    }
//    else
//    {
//        cout << "output file not open" << endl;
//    }
//    inFile.close();
//    outFile.close();
//}
//
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
    cout << "extGCD" << endl;
        PrintBN(a, "a");
        PrintBN(b, "b");
        PrintBN(x, "x");
        PrintBN(y, "y");
        cout << endl;
    //base case
    if(BN_is_zero(a))
    {
        cout << "return" << endl;
        BN_set_word(x, (unsigned long) 0);
        BN_set_word(y, (unsigned long) 1);
        PrintBN(x, "x");
        PrintBN(y, "y");
        PrintBN(b, "b");
        cout << endl;
        return BN_dup(b);
    }
    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *tmp = BN_new();
    BN_mod(tmp, b, a, ctx);
    BIGNUM *gcd = extGCD(tmp, a, x1, y1);

    PrintBN(gcd, "gcd");
    PrintBN(b, "b");
    PrintBN(gcd, "gcd");
    PrintBN(a, "a");
    PrintBN(gcd, "gcd");
    PrintBN(x1, "x1");
    PrintBN(gcd, "gcd");
    PrintBN(y1, "y1");
    PrintBN(gcd, "gcd");
    cout << endl;
    //x = y1 - (b/a)*x1;
    BN_div(tmp, x, b, a, ctx);
    PrintBN(tmp, "b/a");
    PrintBN(gcd, "gcd");
    PrintBN(x, "x");
    PrintBN(gcd, "gcd");
    PrintBN(b, "b");
    PrintBN(gcd, "gcd");
    PrintBN(a, "a");
    PrintBN(gcd, "gcd");
    BN_mul(x1, tmp, x1, ctx);
    PrintBN(tmp, "b/a*x1");
    PrintBN(gcd, "gcd");
    BN_sub(x, y1, tmp);
    PrintBN(tmp, "y1 - (b/a)*x1");
    PrintBN(gcd, "gcd");
    //y = x1;
    y = x1;

    PrintBN(gcd, "return gcd");
    cout << endl;
    return gcd;
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
        BIGNUM *rm = BN_new();
        BIGNUM *temp = BN_new();
        BN_mod(temp, a, b, ctx);
        internal = extEuclid(b, temp);
        tmp[0] = internal[0];
        tmp[1] = internal[2];
        BN_div(temp, rm, a, b, ctx); // a/b
        BN_mul(temp, temp, internal[2], ctx); // (a/b) *internal[2]
        BN_sub(temp, internal[1], temp); //internal[1] - a/b * internal[2];
        tmp[2] = temp;
    //cout << a << " " << b << " " << a/b << " " << tmp[0] << " " << tmp[1] << " " << tmp[2] << endl;
    }

    result[0] = tmp[0];
    result[1] = tmp[1];
    result[2] = tmp[2];

    return result;
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
    //a = e, m = phi
    x = BN_new();
    y = BN_new();
    BIGNUM *g = BN_new();
    g = extGCD(e, phi, x, y);
        PrintBN(x, "x");
        PrintBN(y, "y");
    if(!BN_is_one(g))
    {
        cout << endl;
        PrintBN(g, "g");
        cout << endl;
        cout << "Inverse not found" << endl;
        return;
    }
    else
    {
        PrintBN(phi, "phi");
        //d = (x%phi + phi)%phi 
        BN_mod(x, x, phi, ctx);
        PrintBN(x, "this will be d");
        BN_add(x, x, phi);
        PrintBN(x, "this will be d");
        BN_mod(x, x, phi, ctx); 
        PrintBN(x, "this will be d");
        cout << endl;
    }
}

void rsaCrypto::PrintBN(BIGNUM *val, string text)
{
    cout << endl << text << ": ";
    BN_print_fp(stdout, val);
}