// Sample.cpp

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using CryptoPP::BufferedTransformation;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cerr;
using namespace std;
/* Convert to hex */ 
#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
#include <assert.h>

/* Vietnamese support */
    
/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h> 
#include <fcntl.h>
#else
#endif

/* String convert */
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

/* Integer convert */
#include <sstream>
using std::ostringstream;


/* Integer Computing in Z_p */
#include <iomanip>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>
#include <cryptopp/algebra.h>
/* Read text from a file */
#include <fstream>

/* Vietnames convert function def*/
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring integer_to_wstring (const CryptoPP::Integer& t);

/* Load key from files functions*/
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
void Load(const string& filename, BufferedTransformation& bt);

/* Read/Write plaintext and ciphertext from files*/
string read_string_from_file(const std::string &file_path);
void write_string_into_file(const std::string &file_path, string text);

int main(int argc, char* argv[])
{
    try
    {	
        /*Set mode support Vietnamese*/
	    #ifdef __linux__
	    setlocale(LC_ALL,"");
	    #elif _WIN32
	    _setmode(_fileno(stdin), _O_U16TEXT);
 	    _setmode(_fileno(stdout), _O_U16TEXT);
	    #else
	    #endif
       
        AutoSeededRandomPool rng;
        // Initialize key pair
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        //Load 3072-bit key from files
        LoadPublicKey("rsa-public.key", publicKey);
        LoadPrivateKey("rsa-private.key", privateKey);
                      
        /* RSA parameters n, p, q, e, d*/
        wcout << "===============RSA parameters==================\n\n";
        wcout << "Public modulo n=" << integer_to_wstring(publicKey.GetModulus()) << "\n\n";
        wcout << "Public key e=" << integer_to_wstring(publicKey.GetPublicExponent()) << "\n\n";
        wcout << "Private prime number p=" << integer_to_wstring(privateKey.GetPrime1()) << "\n\n";
        wcout << "Private prime number q=" << integer_to_wstring(privateKey.GetPrime2()) << "\n\n";
        wcout << "Secret key d=" << integer_to_wstring(privateKey.GetPrivateExponent()) << "\n\n";
        wcout << "===============Check the keys==================\n\n";
        // Check the keys
		CryptoPP::Integer n = publicKey.GetModulus();
		CryptoPP::Integer p = privateKey.GetPrime1();
		CryptoPP::Integer q = privateKey.GetPrime2();
		/*CryptoPP::ModularArithmetic ma(n);
		cout << "n = " << rsaPublic.GetModulus() << "\n";
		cout << "p * q = " << ma.Multiply(p, q) << " (mod n)\n"; // nếu p*q == 0 (mod n) thì key đúng */
        CryptoPP::Integer checkKey = a_times_b_mod_c(p, q, n); 
		wcout << "p * q = " << integer_to_wstring(checkKey) << " (mod n)\n";
        if(!checkKey)
            wcout << "Correct RSA key pair !!!!\n\n";
		wcout << "===============RSA Algorithm===================\n\n";
        ////////////////////////////////
        string plain, cipher, recovered, hexCipher; // strings hold plaintext,ciphertext, decrypted text, cipher in hexa
        RSAES_OAEP_SHA_Encryptor e( publicKey );    // RSA Encryption with publicKey 
        RSAES_OAEP_SHA_Decryptor d( privateKey );   // RSA Decryption with publicKey
        wstring wplain, wcipher; // wstrings hold plaintext, ciphertext that support Vietnamese
        
        wstring enter; // Remove enter as the next input
        wcout << "Choose type of Plaintext & Ciphertext input:\n";
        wcout << "\t 1-From screen \t 2-From files\n";
        int input;
        wcout << "Input: ";
        wcin >> input;
        getline(wcin, enter);
        switch (input)
        {
        case 1: // Enter plaintext and ciphertext from screen
            {
                // Enter plaintext
                wcout << "Input Plaintext: ";
                #ifdef _WIN32
                wcin.ignore();
                #else
                #endif
                getline(wcin,wplain);
                plain = wstring_to_string(wplain);
                wcout << "Plaintext: " << wplain << endl;
                
                //Write plaintext to file
                string plaintextFile("plaintext.txt");
                write_string_into_file(plaintextFile, plain);

                // Enter ciphertext
                #ifdef _WIN32
                wcin.ignore();
                #else
                #endif
                wcout << "Input Ciphertext(hex): ";
                getline (wcin, wcipher);
                hexCipher = wstring_to_string(wcipher);

                //Write ciphertext to file
                string ciphertextFile("ciphertext.txt");
                write_string_into_file(ciphertextFile, hexCipher);
            }
            break;
        
        case 2: // Get plaintext and ciphertext from files
            {
                // Read plaintext from file plaintext.txt 
                string plaintextFile("plaintext.txt");
                plain = read_string_from_file(plaintextFile);
                wcout << "Plaintext: " << string_to_wstring(plain) << "\n\n";

                // Read ciphertext from file ciphertext.txt 
                string ciphertextFile("ciphertext.txt");
                hexCipher = read_string_from_file(ciphertextFile);
                wcout << "Ciphertext (hex): " << string_to_wstring(hexCipher) << "\n\n";
                wcout << "Get plaintext and ciphertext from files successfully!!!\n\n";
            }
            break;
        }


        double encTime = 0; //Total time of 10000-round Encryption
        double decTime = 0; //Total time of 10000-round Decryption

        /* Choose mode encryption or decryption */
        wcout << "===============RSA Functions===================\n";
        wcout << "Choose mode:\n";
        wcout << "\t 1.RSA Encryption\n";
        wcout << "\t 2.RSA Decryption\n";
        int mode; 
        wcout << "Mode: ";
        wcin >> mode;
        switch(mode)
        {
            case 1: //RSA Encryption
                {
                    int startEnc = clock(); // Beginning of 10000-round Encryption process
                    int round = 1;  // round count
                    string encoded;
                    while(round <= 10000) // 10000 rounds
                    {
                        // Encryption
                        cipher.clear(); //Remove cipher value after each round
                        StringSource( plain, true,
                            new PK_EncryptorFilter( rng, e,
                                new StringSink( cipher )
                            ) // PK_EncryptorFilter
                        ); // StringSource
                        encoded.clear(); //Remove encoded (cipher in hexa) value after each round
                        StringSource(cipher, true, 
                        new HexEncoder(new StringSink(encoded)) );
                        round++;
                    }
                    int endEnc = clock(); // Ending of 10000-round Encryption process
                    encTime += (endEnc - startEnc) / double(CLOCKS_PER_SEC) * 1000; // Total time of 10000-round Encryption
                    wcout << "Ciphertext: " << string_to_wstring(encoded) << endl; // Print ciphertext
                    //Decryption
                    wcout << "Do you like to decrypt the ciphertext?" <<endl;
                    wcout << "\t 1. YES \t 2.NO \n";
                    int ans;
                    wcout << "Choose: ";
                    wcin >> ans;
                    if(ans == 1)
                    {
                        /* Decrypt */
                        recovered.clear();
                        StringSource( cipher, true,
                            new PK_DecryptorFilter( rng, d,
                                new StringSink(recovered )
                            ) // PK_EncryptorFilter
                        ); // StringSource
                        wcout << "Recovered text:" << string_to_wstring(recovered) << endl; // Print decrypted text after Decryption
                        assert( plain == recovered );
                    }
                    wcout << "RSA Encryption (10000 rounds): " << encTime << " ms" <<endl; // Print total time of 10000-round Encryption
                    wcout << "RSA Encryption (1 round):      " << encTime/10000 << " ms" << endl; // Print average time of encryption process
                }
                break;

            case 2: // RSA Encryption
                {
                    int startDec = clock();  // Beginning of 10000-round Decryption process
                    int round = 1;
                    while(round <= 10000)
                    {
                        cipher.clear();
                        StringSource(hexCipher, true,
                        new HexDecoder(new StringSink(cipher)) );
                        // Decryption
                        recovered.clear();
                        StringSource( cipher, true,
                            new PK_DecryptorFilter( rng, d,
                                new StringSink( recovered )
                            ) // PK_EncryptorFilter
                        ); // StringSource
                        round++;
                    }
                    int endDec = clock(); // Ending of 10000-round Encryption process
                    decTime += (endDec - startDec) / double(CLOCKS_PER_SEC) * 1000; // Total time of 10000-round Decryption
                    wcout << "Recovered text:" << string_to_wstring(recovered) << endl; // Print decrypted text after Decryption
                    wcout << "RSA Decryption (10000 rounds): " << decTime << " ms" <<endl; // Print total time of 10000-round Decryption
                    wcout << "RSA Decryption (1 round):      " << decTime/10000 << " ms" << endl; // Print average time of decryption process
                    assert( plain == recovered );
                }
                break;
        }
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }   
	return 0;
}

/* Convert interger to wstring */
wstring integer_to_wstring (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t; // pump t to oss
    std::string encoded(oss.str()); // to string 
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded); // string to wstring 
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);
	file.TransferTo(bt);
	bt.MessageEnd();
}

/* Read content of a file */
string read_string_from_file(const std::string &file_path) {
    const std::ifstream input_stream(file_path, std::ios_base::binary);

    if (input_stream.fail()) {
        throw std::runtime_error("Failed to open file");
    }

    std::stringstream buffer;
    buffer << input_stream.rdbuf();

    return buffer.str();
}

void write_string_into_file(const std::string &file_path,string text)
{
    std::ofstream file(file_path);
    file << text;
}