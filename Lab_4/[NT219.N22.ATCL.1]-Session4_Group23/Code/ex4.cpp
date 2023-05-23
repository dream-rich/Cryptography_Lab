#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <md5.h>
#include <sha3.h>
#include <sha.h>
#include <shake.h>

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "sha.h"
using CryptoPP::SHA1;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;

using namespace CryptoPP;
using namespace std;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// MD5, SHA224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384,
// SHA3-512, SHAKE128, SHAKE256
void hashMD5(const string& message){
    CryptoPP::byte digest[ Weak::MD5::DIGESTSIZE ];
    Weak::MD5 hash;
    hash.CalculateDigest( digest, (const CryptoPP::byte*)message.c_str(), message.length() );

    HexEncoder encoder;
    string output;

    encoder.Attach( new StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << output << std::endl;
}

void hashSHA224(const string& message){
    SHA224 hash;
    string digest;
    
    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHA256 (const string& message){
    SHA256 hash;
    string digest;
    
    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHA384(const string& message){
    SHA384 hash;
    string digest;
    
    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHA512(const string& message){
    SHA512 hash;
    string digest;
    
    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHA3_224(const string& message){
    string digest;
    SHA3_224 hash;

    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHA3_256(const string& message){
    string digest;
    SHA3_256 hash;

    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHA3_384(const string& message){
    string digest;
    SHA3_384 hash;

    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHA3_512(const string& message){
    string digest;
    SHA3_512 hash;

    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    cout << "Message: " << message << endl;
    cout << "Digest: " << digest << endl;
}

void hashSHAKE128(const string& message){
    std::string digest;
    SHAKE128 hash;

    StringSource(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Message: " << message << std::endl;
    std::cout << "Digest: " << digest << std::endl;
}

void hashSHAKE256(const string& message){
    std::string digest;
    SHAKE256 hash;

    StringSource(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Message: " << message << std::endl;
    std::cout << "Digest: " << digest << std::endl;
}

int main(int argc, char* argv[])
{
    std::string message;
    cout << "Enter message: ";
    getline(cin, message);

    int choice;
    while (choice != 0)
    {
        cout << "Choose hash function: \n";
        cout << "0. Exit\n";
        cout << "1. MD5\n";
        cout << "2. SHA224\n";
        cout << "3. SHA256\n";
        cout << "4. SHA384\n";
        cout << "5. SHA512\n";
        cout << "6. SHA3-224\n";
        cout << "7. SHA3-256\n";
        cout << "8. SHA3-384\n";
        cout << "9. SHA3-512\n";
        cout << "10. SHAKE128\n";
        cout << "11. SHAKE256\n";
        cout << "Enter your choice: ";
        cin >> choice;
        switch (choice)
        {
        case 1:
            hashMD5(message);
            break;
        case 2:
            hashSHA224(message);
            break;  
        case 3:
            hashSHA256(message);
            break;
        case 4:
            hashSHA384(message);
            break;
        case 5:
            hashSHA512(message);
            break;
        case 6:
            hashSHA3_224(message);
            break;
        case 7:
            hashSHA3_256(message);
            break;
        case 8:
            hashSHA3_384(message);
            break;
        case 9:
            hashSHA3_512(message);
            break;
        case 10:
            hashSHAKE128(message);
            break;
        case 11:
            hashSHAKE256(message);
            break;
        default:
            cout << "Invalid choice\n";
            break;
        }
    }
}