#include "hrtimer.h"
#include "rsa.h"
#include "sha.h"
#include "files.h"
#include "osrng.h"
#include "cryptlib.h"
#include <string>
#include <exception>
#include <iostream>
#include <assert.h>

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
    try
    {
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

        // Input plaintext
        std::wstring wplaintext = L"Môn mật mã học\n";

        // Convert UTF-16 to bytes
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::string splaintext = converter.to_bytes(wplaintext);

        SecByteBlock plaintext((const CryptoPP::byte*)splaintext.data(), splaintext.size());

        // Encrypt
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

        // Now that there is a concrete object, we can validate
        assert(0 != encryptor.FixedMaxPlaintextLength());
        assert(SECRET_SIZE <= encryptor.FixedMaxPlaintextLength());

        // Create cipher text space
        size_t ecl = encryptor.CiphertextLength(plaintext.size());
        assert(0 != ecl);
        SecByteBlock ciphertext(ecl);

        // Paydirt
        encryptor.Encrypt(rng, plaintext, plaintext.size(), ciphertext);

        double elapsedTimeInSeconds;
        unsigned long i = 0, blocks = 1;

        CryptoPP::ThreadUserTimer timer;
        timer.StartTimer();

        do{
            blocks *= 2;
            for (; i < blocks; i++)
                encryptor.Encrypt(rng, plaintext.data(), plaintext.size(), ciphertext.data());
            elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
        } while (elapsedTimeInSeconds < runTimeInSeconds);

        const double bytes = static_cast<double>(plaintext.size()) * blocks;
        const double ghz = cpuFreq / 1000 / 1000 / 1000;
        const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
        const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

        std::cout << encryptor.AlgorithmName() << " encrypt benchmarks..." << std::endl;
        std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
        std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
        std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
    }
    catch (CryptoPP::Exception& e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    return 0;
}


