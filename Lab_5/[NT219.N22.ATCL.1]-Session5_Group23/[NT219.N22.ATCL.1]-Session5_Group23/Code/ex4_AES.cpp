#include <iostream>
#include <string>
#include <aes.h>
#include <base64.h>
#include <modes.h>
#include <filters.h>
#include <osrng.h>
#include <hex.h>

int main()
{
    CryptoPP::AutoSeededRandomPool prng;

    std::string ivBase64 = "dkdxdo+eifES0inl0zW/ew==";
    std::string ciphertextBase64 = "MeNQurBA3QKVfCYO34Pbi/ENnjx23hSb0qXkAwbnmWw=";
    std::string plaintext2Base64 = "BCIHH+rpqbBXgQnI/hifA16RcM3ZNLUi0D9kC9qG3o4=";

    std::string iv, ciphertext, plaintext2;

    CryptoPP::StringSource(ivBase64, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(iv)
        )
    );

    CryptoPP::StringSource(ciphertextBase64, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(ciphertext)
        )
    );

    CryptoPP::StringSource(plaintext2Base64, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(plaintext2)
        )
    );

    std::string res;
    std::string t = iv;

    for (size_t i = 0; i < ciphertext.size(); i += 16)
    {
        std::string block = plaintext2.substr(i, 16);
        CryptoPP::xorbuf(reinterpret_cast<CryptoPP::byte*>(&block[0]),
            reinterpret_cast<const CryptoPP::byte*>(&t[0]),
            reinterpret_cast<const CryptoPP::byte*>(&block[0]), 16);
        res += block;
        t = ciphertext.substr(i, 16);
    }

    std::cout << res << std::endl;

    return 0;
}
