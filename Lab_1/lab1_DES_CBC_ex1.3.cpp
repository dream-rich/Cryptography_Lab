#include "osrng.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include "cryptlib.h"
#include "hex.h"
#include "filters.h"
#include "des.h"
#include "modes.h"
#include "secblock.h"

// Library support UTF-16
#include <io.h>
#include <fcntl.h>
// Library string <-> wstring
#include <locale>
#include <codecvt>

using namespace std;
using namespace CryptoPP;

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

int main(int argc, char* argv[]) {
  #ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

  AutoSeededRandomPool prng;

  SecByteBlock key(DES::DEFAULT_KEYLENGTH);
  prng.GenerateBlock(key, key.size());

  CryptoPP::byte iv[DES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  wstring wplain = L"thử nghiệm tiếng Việt";
  string plain = wstring_to_utf8(wplain);

  string cipher, encoded, recovered;

  // Pretty print key
  encoded.clear();
  StringSource(key, key.size(), true,
      new HexEncoder(
        new StringSink(encoded)) // HexEncoder
  ); // StringSource

  wstring encodedKey(encoded.begin(), encoded.end());
  wcout << "key: " << encodedKey << endl;

  // Pretty print iv
  encoded.clear();
  StringSource(iv, sizeof(iv), true,
      new HexEncoder(
        new StringSink(encoded)) // HexEncoder
  ); // StringSource

  wstring encodedIV(encoded.begin(), encoded.end());
  wcout << "iv: " << encodedIV << endl;
  try { 
    wcout << "plain text: " << wplain << endl;
    CBC_Mode< DES >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(plain, true, 
        new StreamTransformationFilter(e,
          new StringSink(cipher)) // StreamTransformationFilter      
    ); // StringSource
  }
  catch(const CryptoPP::Exception& e) {
    cerr << e.what() << endl;
    exit(1);
  }

  // Pretty print
  encoded.clear();
  StringSource(cipher, true,
      new HexEncoder(
        new StringSink(encoded)) // HexEncoder
  ); // StringSource

  wstring encodedCipher(encoded.begin(), encoded.end());
  wcout << "cipher text: " << encodedCipher << endl;

  //* Decryption
  try {
    CBC_Mode< DES >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(cipher, true, 
        new StreamTransformationFilter(d,
          new StringSink(recovered)) // StreamTransformationFilter
    ); // StringSource

    wstring encodedRecovered(recovered.begin(), recovered.end());
    wcout << "recovered text: " << encodedRecovered << endl;
  }
  catch(const CryptoPP::Exception& e) {
    cerr << e.what() << endl;
    exit(1);
  }
  return 0;
}
