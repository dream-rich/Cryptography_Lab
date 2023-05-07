#include "rsa.h"
#include "sha.h"
#include "files.h"
#include "osrng.h"
#include "secblock.h"
#include "cryptlib.h"
#include "base64.h"

#include <string>
#include <exception>
#include <iostream>
#include <assert.h>
#include <locale>

// Library support UTF-16
#include <io.h>
#include <fcntl.h>

#include <codecvt>
#include "files.h"

using namespace CryptoPP;
using namespace std;

// convert UTF-8 string to wstring
wstring utf8_to_wstring(const string &str) {
    using convert_type = std::codecvt_utf8<wchar_t>;
    wstring_convert<convert_type, wchar_t> converter;
    return converter.from_bytes(str);
}

// convert wstring to UTF-8 string
string wstring_to_utf8(const wstring &wstr) {
    using convert_type = std::codecvt_utf8<wchar_t>;
    wstring_convert<convert_type, wchar_t> converter;
    return converter.to_bytes(wstr);
}
string InputFromFile(wstring wfilename)
{
    wcin.ignore();
    string plain, filename;
    filename = wstring_to_utf8(wfilename);
    FileSource file(filename.data(), true, new StringSink(plain));
    return plain;
}

void InputString() {
    // Generate a private/public key pair
    AutoSeededRandomPool rng;
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 1024);
    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);

    // Get the plaintext input from the user
    cin.ignore();
    std::string plaintext;
    std::cout << "Enter plaintext: ";
    std::getline(std::cin, plaintext);

    // Convert the plaintext to byte array
    CryptoPP::byte plaintextBytes[plaintext.length()+1];
    memcpy(plaintextBytes, plaintext.c_str(), plaintext.length()+1);

    // Encrypt the plaintext using the public key
    std::string ciphertext;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    StringSource(plaintextBytes, sizeof(plaintextBytes), true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)));

    // Encode the ciphertext in base64
    std::string encodedCiphertext;
    StringSource s(ciphertext, true,
        new Base64Encoder(
            new StringSink(encodedCiphertext)));

    // Decrypt the ciphertext using the private key
    std::string decryptedtext;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    
    StringSource ss(encodedCiphertext, true,
        new Base64Decoder(
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(decryptedtext))));

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Encoded Ciphertext: " << encodedCiphertext << std::endl;
    std::cout << "Recovered Text: " << decryptedtext << std::endl;
}

void InputUTF16(){
    AutoSeededRandomPool rng;
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 1024);
    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);

    // Get the UTF-16 plaintext input from the user
    wcin.ignore();
    std::wstring wplaintext;
    std::wcout << "Enter plaintext: ";
    std::getline(std::wcin, wplaintext);

    // Convert the UTF-16 plaintext to bytes
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::string plaintext = converter.to_bytes(wplaintext);
    CryptoPP::byte plaintextBytes[plaintext.length()+1];
    memcpy(plaintextBytes, plaintext.c_str(), plaintext.length()+1);

    // Encrypt the plaintext using the public key
    std::string ciphertext;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    StringSource(plaintextBytes, sizeof(plaintextBytes), true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)));

    // Encode the ciphertext in base64
    std::string encodedCiphertext;
    StringSource s(ciphertext, true,
        new Base64Encoder(
            new StringSink(encodedCiphertext)));

    // Decrypt the ciphertext using the private key
    std::string decryptedtext;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    StringSource ss(encodedCiphertext, true,
        new Base64Decoder(
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(decryptedtext))));

    // Convert the decrypted text back to UTF-16
    std::wstring wdecryptedtext = converter.from_bytes(decryptedtext);

    std::wcout << "Plaintext: " << wplaintext << std::endl;
    std::cout << "Encoded Ciphertext: " << encodedCiphertext << std::endl;
    std::wcout << "Recovered Text as UTF-16: " << wdecryptedtext << std::endl;
}

int main()
{
    int choice;
    cout << "1. Input string using utf-8" << endl;
    cout << "2. Input string using utf-16" << endl;
    cin >> choice;
    switch (choice)
    {
    case 1:
        InputString();
        break;
    case 2:
         InputUTF16();
         break;
    default:
        break;
    }

    return 0;
}
