#include "rsa.h"
#include "sha.h"
#include "files.h"
#include "osrng.h"
#include "secblock.h"
#include "cryptlib.h"
#include "base64.h"
#include "queue.h"
#include "hex.h"

#include <string>
#include <exception>
#include <iostream>
#include <assert.h>
#include <fstream>
#include <integer.h>

using namespace std;
using namespace CryptoPP;

string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 4096);
        
        RSA::PrivateKey privateKey;
            FileSource pri("privateKey_ex3.txt",true);
            privateKey.BERDecode(pri);

        RSA::PublicKey publicKey;
            FileSource pub("publicKey_ex3.txt", true);
            publicKey.BERDecode(pub);

        // Input plaintext
        string myPlaintext = "RSA Encryption Schemes";

        cout << "Plaintext: " << myPlaintext << endl;

        // Encrypt
        RSAES_OAEP_SHA_Encryptor encryptor( publicKey );      

        // Create cipher text space
        size_t ecl = encryptor.CiphertextLength( myPlaintext.size() );
        assert( 0 != ecl );
        SecByteBlock ciphertext( ecl );

        // Paydirt
        SecByteBlock plaintext((const CryptoPP::byte*)myPlaintext.data(), myPlaintext.size());
        encryptor.Encrypt( rng, plaintext, plaintext.size(), ciphertext );

        // Write ciphertext to file
        string cipherText((const char*)ciphertext.data(), ciphertext.size());
        ofstream writefile("cipherText.txt");
        writefile << cipherText;
        if(writefile.is_open() && writefile.good())
            std::cout << cipherText << '\n';
        writefile.close();

        cout << "Ciphertext read from file: " << endl;
        ifstream readfile("cipherText.txt");
        if (readfile.is_open())
            while (getline(readfile, cipherText))
                std::cout << cipherText << '\n';

        readfile.close();

        // DECRYPT
        RSAES_OAEP_SHA_Decryptor decryptor( privateKey );

        // Create recovered text space
        size_t dpl = decryptor.MaxPlaintextLength( cipherText.size() );
        assert( 0 != dpl );
        SecByteBlock recovered( dpl );

        // Paydirt
        decryptor.Decrypt( rng, (const CryptoPP::byte*)cipherText.data(), cipherText.size(), recovered );

        string recoveredText((const char*)recovered.data(), recovered.size());
        cout << "Recovered plain text: " << recoveredText << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}
