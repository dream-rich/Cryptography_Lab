// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"
// Library support UTF-16
#include <io.h>
#include <fcntl.h>
// Library string <-> wstring
#include <locale>
#include <codecvt>

using namespace std;
using namespace CryptoPP;

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

int main(int argc, char* argv[])
{
	 #ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

	AutoSeededRandomPool prng;

	/*
	CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	CryptoPP::byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	*/


string skey, siv;
  wstring wkey, wiv;

  SecByteBlock key(8);
  wcout << L"Enter key (8 bits): ";
  fflush(stdin);
  getline(wcin, wkey);
  skey = wstring_to_utf8(wkey);
  for (int i=0; i<8 ;i++) {
    key[i]= (unsigned char) skey[i];
  }

  CryptoPP::byte iv[8];
  wcout << L"Enter iv (8 bits): ";
  fflush(stdin);
  getline(wcin, wiv);
  siv = wstring_to_utf8(wiv);
  for (int i=0; i<8 ;i++) {
    iv[i]= (unsigned char) siv[i];
  }

	//wstring plain = L"Thử nghiệm tiếng việt";

	/*wstring wplain;
	wcout << "Enter input: ";
  	getline(wcin, wplain);*/

	wstring wplain = L"Hồng Nhung 1234567890";
	string plain = wstring_to_utf8(wplain);
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring encodedKey(encoded.begin(), encoded.end());
  	wcout << "key: " << encodedKey << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring encodedIV(encoded.begin(), encoded.end());
  	wcout << "iv: " << encodedIV << endl;

	/*********************************\
	\*********************************/

	try
	{
		wcout << "plain text: " << wplain << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring encodedCipher(encoded.begin(), encoded.end());
  	wcout << "cipher text: " << encodedCipher << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

	wstring encodedRecovered(recovered.begin(), recovered.end());
	wcout << "recovered text: "<< encodedRecovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

