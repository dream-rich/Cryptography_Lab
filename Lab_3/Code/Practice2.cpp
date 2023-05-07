// Sample.cpp
#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSASS;
using CryptoPP::InvertibleRSAFunction;

#include "pssr.h"
using CryptoPP::PSS;

#include "sha.h"
using CryptoPP::SHA1;
using CryptoPP::SHA256;
#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "files.h"
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::FileSource;
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "secblock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <locale>
using std::wstring_convert;

#include <codecvt>
using std::codecvt_utf8;

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "integer.h"
using CryptoPP::Integer;
#include <string>
using std::string;
using std::wstring;
#include <exception>
using std::exception;
#include <iomanip>
using std::hex;
#include <iostream>
using std::cout;
using std::cin;
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;
#include <assert.h>
#include <fstream>


// ===================================================================== //

string HexEncode(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

void PrintSecByteBlock(const SecByteBlock &message)
{
    string encoded;
    StringSource(message, message.size(), true, new HexEncoder(new StringSink(encoded)));
    cout << encoded << endl;
}

string HexEncode(const SecByteBlock &signature){
    string encoded;
    StringSource(signature, signature.size(), true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

void SaveSignatureToFile(SecByteBlock signature , string filename){
    std::ofstream file;
    file.open(filename,std::ios_base::binary);
    assert(file.is_open());
    string s = HexEncode(signature);
    int len = s.length();
    char* char_array = new char[len + 1];
    strcpy(char_array, s.c_str());
    for (int i = 0; i < len; i++)
    {
        file.write(reinterpret_cast<char *>(&char_array[i]),sizeof(char_array[i]));
    }
    delete[] char_array;
    file.close();
}


string GetFileData(string filename)
{
    cin.ignore();
    string data;
    FileSource file(filename.data(), true, new StringSink(data));
    cout << "Reading plaintext from file " << filename << endl;
    return data;
}

// ===================================================================== //
int main(int argc, char* argv[])
{
    try
    {
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 3072);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

        // Message
        string message = GetFileData("DigitalSignature.txt");
        cout << "Message : " << message << endl;
        // Signer object
        RSASS<PSS, SHA256>::Signer signer(privateKey);

        // Create signature space
        size_t length = signer.MaxSignatureLength();
        SecByteBlock signature(length);

        // Sign message
        length = signer.SignMessage(rng, (const byte*) message.c_str(),
            message.length(), signature);

        // Resize now we know the true size of the signature
        signature.resize(length);
        cout << "Signature : ";
        PrintSecByteBlock(signature);
        SaveSignatureToFile(signature,"sample.bin");

    }

    catch( CryptoPP::Exception& e ) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

