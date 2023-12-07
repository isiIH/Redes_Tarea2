#include <fstream>
#include <iostream>
#include <iomanip>

#include "cryptopp-CRYPTOPP_8_9_0/modes.h"
#include "cryptopp-CRYPTOPP_8_9_0/aes.h"
#include "cryptopp-CRYPTOPP_8_9_0/filters.h"

#include "cryptopp-CRYPTOPP_8_9_0/base64.h"
using CryptoPP::Base64Encoder;

#include "cryptopp-CRYPTOPP_8_9_0/filters.h"
using CryptoPP::StringSink;

using namespace std;

#define PRINT 1

int main(int argc, char* argv[]) {

    if(argc != 3){
		cout << "./aes <filename> <bytes>" << endl;
		exit(EXIT_FAILURE);
	}

    string filename = argv[1];
    int bytes = atoi(argv[2]);
    ifstream file(("test/"+filename).c_str());
    string line;
    string plaintext = "";
    while(getline(file, line)) {
        plaintext += line + "\n";
    }
    plaintext = plaintext.substr(0, bytes);

    //Key and IV setup
    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
    //bit). This key is secretly exchanged between two parties before communication   
    //begins. DEFAULT_KEYLENGTH= 16 bytes
    CryptoPP::byte key[ CryptoPP::AES::MAX_KEYLENGTH ];
    CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::MAX_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    //
    // String and Sink setup
    //
    std::string ciphertext;
    std::string decryptedtext;

    //
    // Dump Plain Text
    //
    if(PRINT) {
        std::cout << "Texto original (" << plaintext.size() << " bytes)" << std::endl;
        std::cout << plaintext;
        std::cout << std::endl << std::endl;
    }

    //
    // Create Cipher Text
    //

    auto start_time = chrono::high_resolution_clock::now();

    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new        CryptoPP::StringSink( ciphertext ) );

    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() );
    stfEncryptor.MessageEnd();

    auto end_time = chrono::high_resolution_clock::now();
    cout << "Tiempo de encriptación: " << chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() << endl;

    //
    // Dump Cipher Text
    //
    if(PRINT) {
        std::cout << "Texto Cifrado (" << ciphertext.size() << " bytes)" << std::endl;
        //BASE64
        std::string encoded_ciphered;
        CryptoPP::StringSource(ciphertext, true, new Base64Encoder(new StringSink(encoded_ciphered)));
        std::cout << encoded_ciphered << std::endl;

        //HEX
        // for( int i = 0; i < ciphertext.size(); i++ ) {

        //     std::cout << "0x" << std::hex << (0xFF & static_cast<CryptoPP::byte>(ciphertext[i])) << " ";
        // }

        std::cout << std::endl << std::endl;
    }

    //
    // Decrypt
    //

    start_time = chrono::high_resolution_clock::now();

    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );

    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    stfDecryptor.MessageEnd();

    end_time = chrono::high_resolution_clock::now();
    cout << "Tiempo de desencriptación: " << chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() << endl;
    //
    // Dump Decrypted Text
    //
    if(PRINT) {
        std::cout << "Texto desencriptado: " << std::endl;
        std::cout << decryptedtext;
        std::cout << std::endl << std::endl;
    }

    return 0;
}