// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
#include <assert.h>

#include <iostream>
using std::wcout;
using std::wcin;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;


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

/* Read text from a file */
#include <fstream>

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

/*#if _MSC_VER <= 1200 // VS 6.0
using CryptoPP::ECDSA<ECP, SHA512>;
using CryptoPP::DL_GroupParameters_EC<ECP>;
#endif*/

#include "cryptopp/oids.h"
using CryptoPP::OID;

/* Vietnames convert function def*/
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring integer_to_wstring (const CryptoPP::Integer& t);

/* Read/Write message from files*/
string read_string_from_file(const std::string &file_path);
void write_string_into_file(const std::string &file_path, string text);

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA512>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA512>::PrivateKey& privateKey, ECDSA<ECP, SHA512>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA512>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA512>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA512>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA512>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, SHA512>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA512>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA512>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA512>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, SHA512>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA512>::PublicKey& key, const string& message, const string& signature );

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{
    /*Set mode support Vietnamese*/
	    #ifdef __linux__
	    setlocale(LC_ALL,"");
	    #elif _WIN32
	    _setmode(_fileno(stdin), _O_U16TEXT);
 	    _setmode(_fileno(stdout), _O_U16TEXT);
	    #else
	    #endif
    // Scratch result
    bool result;   
    
    // Private and Public keys
    ECDSA<ECP, SHA512>::PrivateKey privateKey;
    ECDSA<ECP, SHA512>::PublicKey publicKey;

    // Generate key by ECDSA_key_gen.exe 
    // Load key in PKCS#9 and X.509 format
    LoadPrivateKey( "ec.private.key", privateKey );
    LoadPublicKey( "ec.public.key", publicKey );
    
    // Print Domain Parameters and Keys
    wcout << "==============KEY PARAMETERS=================\n";    
    PrintDomainParameters( publicKey );
    PrintPrivateKey( privateKey );
    PrintPublicKey( publicKey );
        
    // Sign and Verify a message      
    wstring wMessage; // wstrings hold message that support Vietnamese
    string message, signature; // message, signature in string format
    wcout << "======================================\n";
    
    // Read message from file message.txt 
    string messFile("message.txt");
    message = read_string_from_file(messFile);
    wcout << "Get message from " << string_to_wstring(messFile) << "!\n\n"; 
    wcout << "Message: " << string_to_wstring(message) << "\n\n";

    wstring enter; // Remove enter as the next input
    wcout << "======================================\n";
    wcout << "Choose mode of ECDSA:\n";
    wcout << "\t1. Signing Function\n";
    wcout << "\t2. Verifying Function\n";
    int mode;
    wcout << "Mode: ";
    wcin >> mode;
    getline(wcin, enter);
    switch(mode)
    {
        case 1:
            {
                double signTime = 0; 
                int start = clock();
                int round = 1;
                while(round <= 10000)
                {
                    result = SignMessage( privateKey, message, signature );
                    round++;
                }
                int end = clock();
                signTime += (end-start)/ double(CLOCKS_PER_SEC) * 1000; // Total time of 10000-round Signing
                string encoded; 
                StringSource( signature, true,
                        new HexEncoder(new StringSink(encoded)));
                wcout << "Signature: " << string_to_wstring(encoded) << endl;
                wcout << "Signing (10000 rounds): " << signTime << " ms\n";
                wcout << "Signing (1 round)     : " << signTime/10000 << " ms\n";
                assert( true == result );
                //Write signature to file
                string signFile("signature.txt");
                write_string_into_file(signFile, signature);
            }
            break;
        case 2:
            {
                // Read signature from file signature.txt 
                string signFile("signature.txt");
                signature = read_string_from_file(signFile);
                wcout << "\nMessage: " << string_to_wstring(message) << "\n\n";
                /* Verifying Functions and Performance*/
                double verTime = 0; 
                int start = clock();
                int round = 1;
                while(round <= 10000)
                {
                    result = VerifyMessage( publicKey, message, signature );
                    round++;
                }
                assert( true == result );
                int end = clock();
                verTime += (end-start)/ double(CLOCKS_PER_SEC) * 1000; // Total time of 10000-round Verifying
                wcout << "Verifying (10000 rounds): " << verTime << " ms\n";
                wcout << "Verifying (1 round)     : " << verTime/10000 << " ms\n";
                if(result)
                    wcout << "Verify message and signature successfully!!!!!\n\n";
                else
                    wcout << "Wrong signature!!!\n\n";
            }
            break;
    } 
    
    return 0;
}


void PrintDomainParameters( const ECDSA<ECP, SHA512>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA512>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    wcout << endl;
 
    wcout << "Modulus:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetField().GetModulus()) << endl;
    
    wcout << "Coefficient A:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetA()) << endl;
    
    wcout << "Coefficient B:" << endl;
    wcout << " " << integer_to_wstring(params.GetCurve().GetB()) << endl;
    
    wcout << "Base Point:" << endl;
    wcout << " X: " << integer_to_wstring(params.GetSubgroupGenerator().x) << endl; 
    wcout << " Y: " << integer_to_wstring(params.GetSubgroupGenerator().y) << endl;
    
    wcout << "Subgroup Order:" << endl;
    wcout << " " << integer_to_wstring(params.GetSubgroupOrder()) << endl;
    
    wcout << "Cofactor:" << endl;
    wcout << " " << integer_to_wstring(params.GetCofactor()) << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA512>::PrivateKey& key )
{   
    wcout << endl;
    wcout << "Private Exponent:" << endl;
    wcout << " " << integer_to_wstring(key.GetPrivateExponent()) << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA512>::PublicKey& key )
{   
    wcout << endl;
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x) << endl; 
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}


void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA512>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA512>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA512>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
   
    signature.erase();    
    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA512>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource

    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA512>::PublicKey& key, const string& message, const string& signature )
{

    bool result = false;
    StringSource( signature+message, true,
    new SignatureVerificationFilter(
        ECDSA<ECP,SHA512>::Verifier(key),
        new ArraySink( (CryptoPP::byte*)&result, sizeof(result) )
    ) // SignatureVerificationFilter
    );
    return result;
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
/* Write content into a file */
void write_string_into_file(const std::string &file_path,string text)
{
    std::ofstream file(file_path);
    file << text;
}