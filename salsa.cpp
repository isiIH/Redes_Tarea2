#include "cryptopp-CRYPTOPP_8_9_0/cryptlib.h"
#include "cryptopp-CRYPTOPP_8_9_0/secblock.h"
#include "cryptopp-CRYPTOPP_8_9_0/salsa.h"
#include "cryptopp-CRYPTOPP_8_9_0/osrng.h"
#include "cryptopp-CRYPTOPP_8_9_0/files.h"
#include "cryptopp-CRYPTOPP_8_9_0/hex.h"

#include <iostream>
#include <fstream>
#include <string>

using namespace CryptoPP;

#define PRINT 1

int main(int argc, char* argv[])
{
    if(argc != 3){
		std::cout << "./salsa <filename> <bytes>" << std::endl;
		exit(EXIT_FAILURE);
	}

    std::string filename = argv[1];
    int bytes = atoi(argv[2]);
    std::ifstream file(("test/"+filename).c_str());
    std::string line;
    std::string plain = "";
    while(getline(file, line)) {
        plain += line + "\n";
    }
    plain = plain.substr(0, bytes);

    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));
    std::string cipher, recover;

    SecByteBlock key(16), iv(8);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::cout << "Key: ";
    encoder.Put((const byte*)key.data(), key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "IV: ";
    encoder.Put((const byte*)iv.data(), iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;
    std::cout << std::endl;

    // Encryption object
    Salsa20::Encryption enc;    
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    // Perform the encryption
    auto start_time = std::chrono::high_resolution_clock::now();

    cipher.resize(plain.size());
    enc.ProcessData((byte*)&cipher[0], (const byte*)plain.data(), plain.size());

    auto end_time = std::chrono::high_resolution_clock::now();
    std::cout << "Tiempo de encriptación: " << std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() << std::endl;
    if(PRINT) {
        
        std::cout << std::endl << "Texto original: " << plain << std::endl;

        std::cout << "Texto Cifrado: ";
        encoder.Put((const byte*)cipher.data(), cipher.size());
        encoder.MessageEnd();
        std::cout << std::endl;
    }

    Salsa20::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    // Perform the decryption
    start_time = std::chrono::high_resolution_clock::now();

    recover.resize(cipher.size());
    dec.ProcessData((byte*)&recover[0], (const byte*)cipher.data(), cipher.size());

    end_time = std::chrono::high_resolution_clock::now();
    std::cout << "Tiempo de desencriptación: " << std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() << std::endl;
    if(PRINT) {
    
        std::cout << std::endl << "Archivo desencriptado: " << recover << std::endl;
    }

    return 0;
}