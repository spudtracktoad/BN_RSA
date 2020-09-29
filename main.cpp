#include <iostream>
#include "rsaCrypto.h"

using namespace std;

int main()
{
    string command;
    string encryptFileName;
    string decryptFileName;

    rsaCrypto* encrypter = new rsaCrypto();

    while(command != "done")
    {
        cout << "Options? ";
        cin >> command;

        if(command == "done")
        {
            break;
        }
        else if(command == "encrypt")
        {
            cout << "encrypt command" << endl;
            cout << "Name of file to encrypt? ";
            cin >> encryptFileName;
            encrypter->encrypt(encryptFileName);

        }
        else if(command == "decrypt")
        {
            cout << "decrypt command" << endl;
            cout << "Name of file to decrypt? ";
            cin >> decryptFileName;
            encrypter->decrypt(decryptFileName);
        }
        else
        {
            cout << "valid commands: done, encrypt, decrypt" << endl;
        }
    }
}