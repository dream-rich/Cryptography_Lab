#include "hrtimer.h"
#include "rsa.h"
#include "sha.h"
#include "files.h"
#include "osrng.h"
#include "cryptlib.h"
#include "aes.h"
#include "ccm.h"

#include <string>
#include <exception>
#include <iostream>
#include <assert.h>

using CryptoPP::CTR_Mode;
using CryptoPP::byte;

// Library support UTF-16
#include <io.h>
#include <fcntl.h>

#include <locale>
#include <codecvt>
#include <hex.h>
#include <files.h>
#include <filters.h>

using namespace std;
using namespace CryptoPP;

const double runTimeInSeconds = 3.0;
const double cpuFreq = 3.3 * 1000 * 1000 * 1000;

int main(int argc, char* argv[])
{
	AutoSeededRandomPool rng;

	// Generate a random AES key and IV
	CryptoPP::byte aes_key[AES::DEFAULT_KEYLENGTH];
	rng.GenerateBlock(aes_key, sizeof(aes_key));

	CryptoPP::byte aes_iv[AES::BLOCKSIZE];
	rng.GenerateBlock(aes_iv, sizeof(aes_iv));

	//input plaintext from file
	std::ifstream plaintextFile("plainText.txt");
	if (!plaintextFile)
	{
		std::cerr << "Failed to open plaintext file" << std::endl;
		return 1;
	}

	string plaintext((std::istreambuf_iterator<char>(plaintextFile)), std::istreambuf_iterator<char>());

	// Encrypt plaintext using AES
	string ciphertext;
	CTR_Mode< AES >::Encryption aes_enc;
	aes_enc.SetKeyWithIV(aes_key, sizeof(aes_key), aes_iv);
	StringSource(plaintext, true, new StreamTransformationFilter(aes_enc, new StringSink(ciphertext)));

	// Generate an RSA key pair
	InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 1024);

    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);

	// Encrypt AES key and IV using RSA public key
	string aes_key_iv;
	aes_key_iv.append((const char*)aes_key, sizeof(aes_key));
	aes_key_iv.append((const char*)aes_iv, sizeof(aes_iv));

	string encrypted_key_iv;
	RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
	StringSource(aes_key_iv, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encrypted_key_iv)));

	// Concatenate encrypted AES key/IV and ciphertext
	string encrypted_message;
	encrypted_message.append(encrypted_key_iv);
	encrypted_message.append(ciphertext);

	// Decrypt AES key and IV using RSA private key
	string decrypted_key_iv;
	RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
	StringSource(encrypted_key_iv, true,
		new PK_DecryptorFilter(rng, decryptor,
			new StringSink(decrypted_key_iv)
		)
	);

	//Benchmark
	double elapsedTimeInSeconds;
	unsigned long i = 0, blocks = 1;

	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();
	//benchmark encryption
	try
	{
		do
		{
			blocks *= 2;
			for (; i < blocks; i++)
				StringSource(aes_key_iv, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encrypted_key_iv)));
			elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
		} while (elapsedTimeInSeconds < runTimeInSeconds);

		const double bytes = static_cast<double>(aes_key_iv.size()) * blocks;
		const double ghz = cpuFreq / 1000 / 1000 / 1000;
		const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
		const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

		std::cout << encryptor.AlgorithmName() << " encrypt benchmarks..." << std::endl;
		std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
		std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
		std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	}
	catch (CryptoPP::Exception& ex)
	{
		std::cerr << ex.what() << std::endl;
	}

	timer.StartTimer();
	//benchmark encryption
	try
	{
		do
		{
			blocks *= 2;
			for(; i < blocks; i++)
				aes_enc.SetKeyWithIV(aes_key, sizeof(aes_key), aes_iv);
				StringSource(plaintext, true,
					new StreamTransformationFilter(aes_enc,
						new StringSink(ciphertext)
					)
				);
			elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
		} while (elapsedTimeInSeconds < runTimeInSeconds);

		const double bytes = static_cast<double>(plaintext.size()) * blocks;
		const double ghz = cpuFreq / 1000 / 1000 / 1000;
		const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
		const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

		std::cout << aes_enc.AlgorithmName() << " plaintext encrypt benchmarks..." << std::endl;
		std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
		std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
		std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	}
	catch (CryptoPP::Exception& ex)
	{
		std::cerr << ex.what() << std::endl;
	}
	return 0;
}

