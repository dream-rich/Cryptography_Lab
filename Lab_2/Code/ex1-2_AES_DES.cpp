#include <iostream>
#include <string>
#include <cstdlib>
#include "include/secblock.h"
#include "include/hrtimer.h"
#include "include/osrng.h"
#include "include/modes.h"
#include "include/aes.h"
#include "include/des.h"
#include "include/cryptlib.h"
#include "include/hex.h"
#include "include/filters.h"
#include "include/ccm.h"
#include "assert.h"
#include <ctime>
using namespace std;
using namespace CryptoPP;
using CryptoPP::CTR_Mode;

const double runTimeInSeconds = 3.0;
const double cpuFreq = 3.3 * 1000 * 1000 * 1000;


void AESencryptionTime (){
	using namespace CryptoPP;
    AutoSeededRandomPool prng;

    SecByteBlock key(16);
    prng.GenerateBlock(key, key.size());
    
    CTR_Mode<AES>::Encryption cipher;
    cipher.SetKeyWithIV(key, key.size(), key);

    const int BUF_SIZE = RoundUpToMultipleOf(2048U,
        dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    ThreadUserTimer timer;
    timer.StartTimer();

    do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            cipher.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::cout << "AES Encryption: " << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
}

void AESdecryptionTime(){
	using namespace CryptoPP;
    AutoSeededRandomPool prng;

    SecByteBlock key(16);
    prng.GenerateBlock(key, key.size());
    
    CTR_Mode<AES>::Decryption cipher;
    cipher.SetKeyWithIV(key, key.size(), key);

    const int BUF_SIZE = RoundUpToMultipleOf(2048U,
        dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    ThreadUserTimer timer;
    timer.StartTimer();

    do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            cipher.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::cout << "AES Decryption: " << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
}

void DESencryptionTime(){
	using namespace CryptoPP;
	AutoSeededRandomPool prng;

	SecByteBlock key(8);
	prng.GenerateBlock(key, key.size());
	
	CTR_Mode<DES>::Encryption cipher;
	cipher.SetKeyWithIV(key, key.size(), key);

	const int BUF_SIZE = RoundUpToMultipleOf(2048U,
		dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());

	AlignedSecByteBlock buf(BUF_SIZE);
	prng.GenerateBlock(buf, buf.size());

	double elapsedTimeInSeconds;
	unsigned long i=0, blocks=1;

	ThreadUserTimer timer;
	timer.StartTimer();

	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			cipher.ProcessString(buf, BUF_SIZE);
		elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
	}
	while (elapsedTimeInSeconds < runTimeInSeconds);

	const double bytes = static_cast<double>(BUF_SIZE) * blocks;
	const double ghz = cpuFreq / 1000 / 1000 / 1000;
	const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
	const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::cout << "DES Encryption: " << std::endl;
	std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
	std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
	std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
}

void DESdecryptionTime(){
	using namespace CryptoPP;
	AutoSeededRandomPool prng;

	SecByteBlock key(8);
	prng.GenerateBlock(key, key.size());
	
	CTR_Mode<DES>::Decryption cipher;
	cipher.SetKeyWithIV(key, key.size(), key);

	const int BUF_SIZE = RoundUpToMultipleOf(2048U,
		dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());

	AlignedSecByteBlock buf(BUF_SIZE);
	prng.GenerateBlock(buf, buf.size());

	double elapsedTimeInSeconds;
	unsigned long i=0, blocks=1;

	ThreadUserTimer timer;
	timer.StartTimer();

	do
	{
		blocks *= 2;
		for (; i<blocks; i++)
			cipher.ProcessString(buf, BUF_SIZE);
		elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
	}
	while (elapsedTimeInSeconds < runTimeInSeconds);

	const double bytes = static_cast<double>(BUF_SIZE) * blocks;
	const double ghz = cpuFreq / 1000 / 1000 / 1000;
	const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
	const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::cout << "DES Decryption: " << std::endl;
	std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
	std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
	std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
}

int main(int argc, char* argv[])
{
	DESencryptionTime();
	AESencryptionTime();
	DESdecryptionTime();
	AESdecryptionTime();
}

