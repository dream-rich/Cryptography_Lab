// g++ -g3 -ggdb -O0 -DDEBUG -Wall -Wextra cryptopp-test.cpp -o cryptopp-test.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -Wall -Wextra cryptopp-test.cpp -o cryptopp-test.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDSA;

#include "sha.h"
using CryptoPP::SHA256;

#include "queue.h"
using CryptoPP::ByteQueue;

#include "oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "asn.h"
using namespace CryptoPP::ASN1;

#include "integer.h"
using CryptoPP::Integer;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA256>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource s(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

int main( int, char** ) {

    AutoSeededRandomPool prng;
    ByteQueue privateKey, publicKey;

    // Generate private key
    ECDSA<ECP, SHA256>::PrivateKey privKey;
    LoadPrivateKey("ec.private.key", privKey);
    privKey.Save( privateKey );

    // Create public key
    ECDSA<ECP, SHA256>::PublicKey pubKey;
    LoadPublicKey("ec.public.key", pubKey);
    pubKey.Save( publicKey );

    // Load private key (in ByteQueue, PKCS#8 format)
    ECDSA<ECP, SHA256>::Signer signer( privateKey );

    // Read the PNG image file into memory
    string filename = "UIT.png";
    string message;
    CryptoPP::FileSource file(filename.c_str(), true, new CryptoPP::StringSink(message));

    // Determine maximum size, allocate a string with that size
    size_t siglen = signer.MaxSignatureLength();
    string signature(siglen, 0x00);

    // Sign, and trim signature to actual size
    siglen = signer.SignMessage( prng, (const CryptoPP::byte*)message.data(), message.size(), (CryptoPP::byte*)signature.data() );
    signature.resize(siglen); 

    cout << "Signature: " << ToHex(signature) << endl;

    // Load public key (in ByteQueue, X509 format)
    ECDSA<ECP, SHA256>::Verifier verifier( publicKey );

    bool result = verifier.VerifyMessage( (const CryptoPP::byte*)message.data(), message.size(), (const CryptoPP::byte*)signature.data(), signature.size() );
    if(result)
        cout << "Verified signature on message" << endl;
    else
        cerr << "Failed to verify signature on message" << endl;

    return 0;
}
