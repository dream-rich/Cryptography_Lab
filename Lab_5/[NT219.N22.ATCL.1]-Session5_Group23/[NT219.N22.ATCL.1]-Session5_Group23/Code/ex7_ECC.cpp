#include <assert.h>

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "aes.h"
using CryptoPP::AES;

#include "integer.h"
using CryptoPP::Integer;

#include "sha.h"
using CryptoPP::SHA1;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "oids.h"
using CryptoPP::OID;
using CryptoPP::byte;

#include <fstream>
#include <iterator>
#include <vector>
#include "filters.h"
#include "base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::StringSource;
using CryptoPP::StringSink;

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key );
bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature );

int main(int argc, char* argv[])
{
    //Load public key
    ECDSA<ECP, SHA1>::PublicKey publicKey;
    LoadPublicKey( "ec.public.key", publicKey ); 

    //Load message
    std::ifstream inputFile("uit.png", std::ios::binary);
    std::vector<char> msbytes(
         (std::istreambuf_iterator<char>(inputFile)),
         (std::istreambuf_iterator<char>()));
    inputFile.close();
    string message(msbytes.begin(),msbytes.end());

    //Encode message
    string encoded;
    CryptoPP::StringSource(message, true, 
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded)));

    //Verify message
    std::vector<string> lsdir = {"0eccaf9b4a71a84fc1f36733d47c5147", "6dc251932a97988e3a420f2bbe9143aa", "8b61860d79c2a96ec81829a68d8060ef", "0256f2c4a2666f0e795c216e6c90f9f3", "369e5feed49bfa0de17b40f9f939d566", "566e9c1e95f786c06570a556e83abdc7", "a7f6df12eeb641b179b9c885b5ba262b", "ab5f656849484cef6b157b5ededf4cf9", "ccd26dcb9c0a9196d708fa3cfa5c25eb", "d20f6fa3834061f881ec816ca7afb35a"};
    for (int i = 0; i < 10; i++){
        bool result = false;  
        string filename = lsdir[i];
        
        std::ifstream siginp(filename, std::ios::binary);
        std::vector<char> sigbytes(
            (std::istreambuf_iterator<char>(siginp)),
            (std::istreambuf_iterator<char>()));
        siginp.close();

        string signature(sigbytes.begin(),sigbytes.end());

        result = VerifyMessage( publicKey, encoded, signature );
        string result_str = (result) ? "true" : "false";
        cout << filename << " " << result_str << endl;
    }
    return 0;
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA1>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA1>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );

    return result;
}
