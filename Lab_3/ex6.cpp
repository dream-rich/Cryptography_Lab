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
#include <locale>

using namespace CryptoPP;
using namespace std;


void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

int main(int argc, char* argv[])
{
    try
    {
        // Generate keys
        AutoSeededRandomPool rng;

        RSA::PrivateKey PrivateKey;
        LoadPrivateKey("private_key.key",PrivateKey);
        RSA::PublicKey PublicKey;
        LoadPublicKey("public_key.key",PublicKey);

        string plain, cipher, recovered;
        cout << "Enter plaintext: ";
        getline(std::cin, plain);

        cout << "Plain Text : " << plain << endl;

        // Encryption
        RSAES_OAEP_SHA_Encryptor enc( PublicKey );

        StringSource( plain, true, new PK_EncryptorFilter( rng, enc, new StringSink( cipher )) ); 
        cout << "Cipher Text : " << ToHex(cipher) << endl;

        // Decryption
        RSAES_OAEP_SHA_Decryptor dec( PrivateKey );

        StringSource( cipher, true, new PK_DecryptorFilter( rng, dec, new StringSink( recovered )) ); 

        assert( plain == recovered );
        cout << "Recovered Text : " << recovered << endl;
    }
    catch( CryptoPP::Exception& enc )
    {
        cerr << "Caught Exception..." << endl;
        cerr << enc.what() << endl;
    }

	return 0;
}
