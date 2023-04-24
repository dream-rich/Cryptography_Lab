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
#include "include/ctr.h"
#include "assert.h"
#include <ctime>
using namespace std;
using namespace CryptoPP;
using CryptoPP::CTR_Mode;

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

void pause()
{
	#ifdef __linux__
		wcout << "Press any key to resume ...";
		wcin.get();
		wcout << endl;
	#elif _WIN32
		system("pause");
	#else
	#endif
}

int main(int argc, char* argv[]){
    #ifdef  __linux__ // For linux
        setlocale(LC_ALL, "");
    #elif _WIN32 	  // For windows
     _setmode(_fileno(stdin), _O_U16TEXT);
     _setmode(_fileno(stdout), _O_U16TEXT);
    #endif

    wcout << "=== AES CTR Mode ===" << endl;

    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key,key.size());
    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv,iv.size());

    //plain1.txt data < 64 bit
	string plain = InputFromFile(L"plain1.txt");
    wcout << "Data < 64 bit" << endl;

	//plain2.txt data utf-16
	// string plain = InputFromFile(L"plain2.txt");
    // wcout << "Data utf-16" << endl;

	//plain3.txt data > 1MB
	// string plain = InputFromFile(L"plain3.txt");
    // wcout << "Data > 1MB" << endl;

    string cipher, encoded, recovered;

    // Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true, new HexEncoder(new StringSink(encoded)));
    wstring encodedKey(encoded.begin(), encoded.end());
	wcout << "key: " << encodedKey << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded))); 
    wstring encodedIV(encoded.begin(), encoded.end());
	wcout << "iv: " << encodedIV << endl;
    
    //Encryption
    CTR_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);

    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));

    #if 0
        StreamTransformationFilter filter(e);
        filter.Put((const byte*)plain.data(), plain.size());
        filter.MessageEnd();

        const size_t ret = filter.MaxRetrievable();
        cipher.resize(ret);
        filter.Get((byte*)cipher.data(), cipher.size());
    #endif
    

    // Pretty print
    encoded.clear();
    StringSource(cipher, true, new HexEncoder(new StringSink(encoded))); 
    wstring encodedCipher(encoded.begin(), encoded.end());
    //wcout << "cipher text: " << encodedCipher << endl;

    //Decryption
    CTR_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);

    StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));

    #if 0
        StreamTransformationFilter filter(d);
        filter.Put((const byte*)cipher.data(), cipher.size());
        filter.MessageEnd();

        const size_t ret = filter.MaxRetrievable();
        recovered.resize(ret);
        filter.Get((byte*)recovered.data(), recovered.size());
    #endif

    // wstring encodedRecoverd(recovered.begin(), recovered.end());
    // wcout << "recovered text: "<< encodedRecoverd << endl;


    // =======================================================================//
	// Benchmark
	// =======================================================================//

    const int BUF_SIZE = RoundUpToMultipleOf(2048U,dynamic_cast<StreamTransformation&>(d).OptimalBlockSize());
    const double runTimeInSeconds = 3.0;
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
            d.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);
    const double cpuFreq = 3.3 * 1000 * 1000 * 1000;
    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    wcout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;

    pause();

  return 0;
}