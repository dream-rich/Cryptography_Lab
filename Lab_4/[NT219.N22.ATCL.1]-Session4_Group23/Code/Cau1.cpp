// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
//

//#include "stdafx.h"

#include <assert.h>

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "include/cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/integer.h"
using CryptoPP::Integer;

#include "include/cryptopp/sha.h"
using CryptoPP::SHA1;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "include/cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#if _MSC_VER <= 1200 // VS 6.0
CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey privateKey;
CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey publicKey;
#endif

#include "include/cryptopp/oids.h"
using CryptoPP::OID;

using namespace std;

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature );

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{
    // Scratch result
    bool result = false;   
    
    // Private and Public keys
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    ECDSA<ECP, SHA1>::PublicKey publicKey;
    
    /////////////////////////////////////////////
    // Generate Keys
    result = GeneratePrivateKey( CryptoPP::ASN1::secp160r1(), privateKey );
    assert( true == result );
    if( !result ) { return -1; }

    result = GeneratePublicKey( privateKey, publicKey );
    assert( true == result );
    if( !result ) { return -2; }
    
    /////////////////////////////////////////////
    // Print Domain Parameters and Keys   
    PrintDomainParameters( publicKey );
    PrintPrivateKey( privateKey );
    PrintPublicKey( publicKey );
    
    /////////////////////////////////////////////
    // Save key in PKCS#9 and X.509 format    
    //SavePrivateKey( "ec.private.key", privateKey );
    //SavePublicKey( "ec.public.key", publicKey );
    
    /////////////////////////////////////////////
    // Load key in PKCS#9 and X.509 format     
    //LoadPrivateKey( "ec.private.key", privateKey );
    //LoadPublicKey( "ec.public.key", publicKey );

    /////////////////////////////////////////////
    // Print Domain Parameters and Keys    
    // PrintDomainParameters( publicKey );
    // PrintPrivateKey( privateKey );
    // PrintPublicKey( publicKey );
        
    /////////////////////////////////////////////
    // Sign and Verify a message      
    // string message = "Yoda said, Do or do not. There is no try.";
    // string signature;
    string input = "D:/Nam2/MMH/Lab_Run/UIT.png";
    string message;

    CryptoPP::FileSource file(input.c_str(), true /*pumpAll*/,new CryptoPP::StringSink(message));
    string signature;

    result = SignMessage( privateKey, message, signature );
    assert(true == result );
    if (true == result)
        std::cout << "Signed\n";
   
    string message_bin;
    CryptoPP::StringSource source(message, true, new CryptoPP::StringSink(message_bin));
    string output = "D:/Nam2/MMH/Lab_Run/output_UIT.png";

    // Write the binary data to the output file
    ofstream outputFile(output, ios::binary);
    if (outputFile.is_open()) {
    outputFile.write(message_bin.data(), message_bin.size());
    outputFile.close();
    std::cout << "Saved the message as a PNG file: " << output << endl;
    } else  {
        cout << "Failed to open the output file: " << output << endl;
    }


    result = VerifyMessage( publicKey, message, signature );
    assert(true == result );
    if (true == result)
        cout << "Verify Success\n";

    return 0;
    // result = SignMessage( privateKey, message, signature );
    // assert( true == result );

    // result = VerifyMessage( publicKey, message, signature );
    // assert( true == result );

    // return 0;
}

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
     
    return key.Validate( prng, 3 );
}

bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl; 
    cout << " Y: " << key.GetPublicElement().y << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
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
            new ArraySink( (CryptoPP::byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );

    return result;
}
