// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp && strip --strip-all cryptopp-key-gen.exe
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>
#include <iomanip>

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <stdexcept>
using std::runtime_error;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Hỗ trợ tiếng Việt */
/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
// Convert string
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

// Integer convert
#include <sstream>
using std::ostringstream;

// Vietnamese functions
wstring integer_to_wstring(const CryptoPP::Integer& t);
wstring string_to_wstring(const std::string& str);
string wstring_to_sstring(const std::wstring& str);

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);

void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

int main(int argc, char** argv)
{
	/*Set mode support Vietnamese*/
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	//std::ios_base::sync_with_stdio(false);

	// http://www.cryptopp.com/docs/ref/class_auto_seeded_random_pool.html
	AutoSeededRandomPool rnd;

	try
	{
		// http://www.cryptopp.com/docs/ref/rsa_8h.html
		RSA::PrivateKey rsaPrivate;
		rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

		RSA::PublicKey rsaPublic(rsaPrivate);

		SavePrivateKey("rsa-private.key", rsaPrivate);
		SavePublicKey("rsa-public.key", rsaPublic);
		// test Vietnamsese
		wstring test;
		wcout << "Type input: ";
		getline(wcin, test);
		wcout << "Input: " << test << "\n";
		/* Pretty print n,p,q,e,d */
		wcout << "n = " << integer_to_wstring(rsaPublic.GetModulus()) << "\n";
		wcout << "e = " << integer_to_wstring(rsaPublic.GetPublicExponent()) << "\n";
		wcout << "p = " << integer_to_wstring(rsaPrivate.GetPrime1()) << "\n";
		wcout << "q = " << integer_to_wstring(rsaPrivate.GetPrime2()) << "\n";
		wcout << "d = " << integer_to_wstring(rsaPrivate.GetPrivateExponent()) << "\n";
		// Check the keys
		CryptoPP::Integer n = rsaPublic.GetModulus();
		CryptoPP::Integer p = rsaPrivate.GetPrime1();
		CryptoPP::Integer q = rsaPrivate.GetPrime2();
		/*CryptoPP::ModularArithmetic ma(n);
		cout << "n = " << rsaPublic.GetModulus() << "\n";
		cout << "p * q = " << ma.Multiply(p, q) << " (mod n)\n"; // nếu p*q == 0 (mod n) thì key đúng */
		wcout << "p * q = " << integer_to_wstring(a_times_b_mod_c(p, q, n)) << " (mod n)\n";
		
 		////////////////////////////////////////////////////////////////////////////////////

		// http://www.cryptopp.com/docs/ref/struct_d_s_a.html
		DSA::PrivateKey dsaPrivate;
		dsaPrivate.GenerateRandomWithKeySize(rnd, 1024);

		DSA::PublicKey dsaPublic;
		dsaPrivate.MakePublicKey(dsaPublic);

		SavePrivateKey("dsa-private.key", dsaPrivate);
		SavePublicKey("dsa-public.key", dsaPublic);

		////////////////////////////////////////////////////////////////////////////////////

		RSA::PrivateKey r1, r2;
		r1.GenerateRandomWithKeySize(rnd, 3072);

		SavePrivateKey("rsa-roundtrip.key", r1);
		LoadPrivateKey("rsa-roundtrip.key", r2);

		r1.Validate(rnd, 3);
		r2.Validate(rnd, 3);

		if(r1.GetModulus() != r2.GetModulus() ||
		   r1.GetPublicExponent() != r2.GetPublicExponent() ||
		   r1.GetPrivateExponent() != r2.GetPrivateExponent())
		{
			throw runtime_error("key data did not round trip");
		}
		
		////////////////////////////////////////////////////////////////////////////////////

		wcout << "Successfully generated and saved RSA and DSA keys" << endl;
	}

	catch(CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch(std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
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

void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string& filename, BufferedTransformation& bt)
{
	throw runtime_error("Not implemented");
}

/* Convert interger to wstring */
wstring integer_to_wstring (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t; // pumb t to oss
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
