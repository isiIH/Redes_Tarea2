using namespace std;

#define PRINT 1

#include "cryptopp-CRYPTOPP_8_9_0/stdafx.h"

#include "cryptopp-CRYPTOPP_8_9_0/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp-CRYPTOPP_8_9_0/base64.h"
using CryptoPP::Base64Encoder;

#include "cryptopp-CRYPTOPP_8_9_0/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::BufferedTransformation;
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

#include "cryptopp-CRYPTOPP_8_9_0/sha.h"
using CryptoPP::SHA1;

#include "cryptopp-CRYPTOPP_8_9_0/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp-CRYPTOPP_8_9_0/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp-CRYPTOPP_8_9_0/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp-CRYPTOPP_8_9_0/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp-CRYPTOPP_8_9_0/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);    
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);    
}

void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void SavePublicKey(const string& filename, const RSA::PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void SavePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

int main(int argc, char* argv[]) {

    if(argc != 3){
		cout << "./rsa <filename> $((2**n))" << endl;
		exit(EXIT_FAILURE);
	}

    string filename = argv[1];
    int bytes = atoi(argv[2]);
    ifstream file(("test/"+filename).c_str());
    string plain;
    getline(file, plain);
    plain = plain.substr(0,bytes);
    // while(getline(file, line)) {
    //     plain += line + "\n";
    // }

    try
    {
        
        ////////////////////////////////////////////////
        // Generate keys
        double total_time = 0;
        auto start_time = chrono::high_resolution_clock::now();
        AutoSeededRandomPool rng;

        // InvertibleRSAFunction parameters;
        // parameters.GenerateRandomWithKeySize( rng, 1024 );

        // RSA::PrivateKey privateKey( parameters );
        // RSA::PublicKey publicKey( parameters );
        RSA::PublicKey publicKey2;
        RSA::PrivateKey privateKey2;

        // SavePublicKey("public_key/key32768.key", publicKey);
        LoadPublicKey("public_key/key32768.key", publicKey2);

        // SavePrivateKey("private_key/key32768.key", privateKey);
        LoadPrivateKey("private_key/key32768.key", privateKey2);

        auto end_time = chrono::high_resolution_clock::now();

        cout << "Tiempo de generación de claves: " << chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() << " microsegundos" << endl;
        
        total_time += chrono::duration_cast<chrono::microseconds>(end_time - start_time).count();

        string cipher, recovered;

        std::cout << "\nTexto original (" << plain.size() << " bytes)" << std::endl;
        if(PRINT) {
            std::cout << plain;
            std::cout << std::endl << std::endl;
        }

        ////////////////////////////////////////////////
        // Encryption
        start_time = chrono::high_resolution_clock::now();
        RSAES_OAEP_SHA_Encryptor e( publicKey2 );

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
        end_time = chrono::high_resolution_clock::now();
        cout << "Tiempo de encriptación: " << chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() << " microsegundos" << endl;
        total_time += chrono::duration_cast<chrono::microseconds>(end_time - start_time).count();

        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        std::cout << "Texto cifrado (" << cipher.size() << " bytes)" << std::endl;
        if(PRINT) {
            //BASE64
            std::string encoded_ciphered;
            CryptoPP::StringSource(cipher, true, new Base64Encoder(new StringSink(encoded_ciphered)));
            std::cout << encoded_ciphered << std::endl;

            //HEX
            // for( int i = 0; i < cipher.size(); i++ ) {

            //     std::cout << "0x" << std::hex << (0xFF & static_cast<CryptoPP::byte>(cipher[i])) << " ";
            // }

            // std::cout << std::endl << std::endl;
        }

        ////////////////////////////////////////////////
        // Decryption
        start_time = chrono::high_resolution_clock::now();
        RSAES_OAEP_SHA_Decryptor d( privateKey2 );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource
        end_time = chrono::high_resolution_clock::now();
        cout << "Tiempo de desencriptación: " << chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() << " microsegundos" << endl;
        total_time += chrono::duration_cast<chrono::microseconds>(end_time - start_time).count();

        assert( plain == recovered );
         
        if(PRINT) {
            std::cout << "Decrypted Text: " << std::endl;
            std::cout << recovered;
            std::cout << std::endl << std::endl;
        }

        cout << "Tiempo total de ejecución (segundos): " << total_time / 1e6 << endl;
        cout << "Tiempo total de ejecución (microsegundos): " << total_time << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}