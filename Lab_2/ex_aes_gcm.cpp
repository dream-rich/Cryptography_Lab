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
#include "include/gcm.h"
#include "assert.h"
#include <ctime>
using namespace std;
using namespace CryptoPP;


// Library support UTF-16
#include <io.h>
#include <fcntl.h>
// Library string <-> wstring
#include <locale>
#include <codecvt>
#include <chrono>
#include <thread>

#include <iomanip>
#include <fstream>
#include "hrtimer.h"
using CryptoPP::ThreadUserTimer;
#include "files.h"

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

// convert UTF-8 string to wstring
wstring utf8_to_wstring(const string &str) {
    using convert_type = std::codecvt_utf8<wchar_t>;
    wstring_convert<convert_type, wchar_t> converter;
    return converter.from_bytes(str);
}

// convert wstring to UTF-8 string
string wstring_to_utf8(const wstring &wstr) {
    using convert_type = std::codecvt_utf8<wchar_t>;
    wstring_convert<convert_type, wchar_t> converter;
    return converter.to_bytes(wstr);
}

string InputFromFile(wstring wfilename)
{
    wcin.ignore();
    string plain, filename;
    filename = wstring_to_utf8(wfilename);
    FileSource file(filename.data(), true, new StringSink(plain));
    return plain;
}

template<typename T> 
void benchmark(T &cipher, AlignedSecByteBlock &data, const int size) {
    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    ThreadUserTimer timer;
    timer.StartTimer();

    do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            cipher.ProcessData(data, data, size);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double cpuFreq = 3.3 * 1000 * 1000 * 1000;
    const double bytes = static_cast<double>(size) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    wcout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;
}
 
template<typename T> 
void benchmarkLess64(T &cipher, AutoSeededRandomPool &prng) {
    // string plaintext = InputFromFile(L"plain1.txt");
    wcout << "Data < 64 bit" << endl;
    const int BUF_SIZE = RoundUpToMultipleOf(64U,
        dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());
    benchmark<T>(cipher, buf, BUF_SIZE);
}

template<typename T>
void benchmarkUtf16(T &cipher, AutoSeededRandomPool &prng) {
    wcout << "Data utf-16" << endl;

    wstring wplain = L"Môn mật mã học\n";
    string plain = wstring_to_utf8(wplain);

    const int BUF_SIZE = RoundUpToMultipleOf(2048U,
        dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    benchmark<T>(cipher, buf, BUF_SIZE);
}

template<typename T>
void benchmarkLarger1MB(T &cipher, AutoSeededRandomPool &prng) {
    wcout << "Data > 1MB" << endl;
    const int MB_SIZE = 5;
    const int DATA_SIZE = MB_SIZE * 1024 * 1024; 

    AlignedSecByteBlock data(DATA_SIZE);
    prng.GenerateBlock(data, data.size());
    benchmark(cipher, data, DATA_SIZE);
}

template<typename T> 
void benchmarkMode(T &cipher, AutoSeededRandomPool &prng) {
    benchmarkLess64<T>(cipher, prng);
    std::cout << '\n';
    benchmarkUtf16<T>(cipher, prng);
    std::cout << '\n';
    benchmarkLarger1MB<T>(cipher, prng);
    std::cout << '\n';
}

int main() {
    wcout << "=== AES GCM Mode ===" << endl;

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(16);
    
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, iv.size());
    
    //Encryption
    GCM<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    benchmarkMode(e, rng);

    return 0;
}
