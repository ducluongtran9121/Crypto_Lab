// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include <codecvt>
#include <locale>
#include <io.h>
#include <fcntl.h>

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using namespace std;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::byte;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::byte;
using CryptoPP::SecByteBlock;

AutoSeededRandomPool prng;						 // Khởi tạo đối tượng prng để gọi hàm GenerateBlock thực hiện random key và initialization vector
SecByteBlock key(DES::DEFAULT_KEYLENGTH);		 // Khởi tạo key có độ dài 8-byte
byte iv[DES::BLOCKSIZE];						 // Khởi tạo initialization vector có độ dài 8-byte
string cipher, recovered;						 // biến cipher lưu bản mã của plaintext
												 // biến recovered lưu bản rõ (sau khi giải mã)
string encodedKey;								 // biến encodedKey lưu key dưới dạng hexa
string encodedIV;								 // biến encodedIV lưu iv dưới dạng hexa
string encodedCipher;							 // biến encodedCipher lưu cipher dưới dạng hexa
wstring wencodedKey, wencodedIV, wencodedCipher; // các biến lưu dạng wstring tương ứng các string ở trên

// convert UTF-8 string to wstring
std::wstring utf8_to_wstring(const std::string &str)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
	return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
std::string wstring_to_utf8(const std::wstring &str)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
	return myconv.to_bytes(str);
}

// ECB MODE : ENCRYPTION, DECRYPTION, TIME
double encTimeECB(string plain)
{
	/*********************************\
	\*********************************/
	int start_s = clock(); // Lấy mốc thời gian bắt đầu mã hóa
	double eTime;		   //Khai báo biến lưu thời gian mã hóa
	try
	{
		//cout << "plain text: " << plain << endl;

		ECB_Mode<DES>::Encryption e; // khai báo biến e thuộc struct ECB_Mode<DES>::Encryption
									 // dùng để thực hiện các hàm mã hóa ECB mode
		e.SetKey(key, key.size());	 // e gọi hàm SetKey với tham số là biến key dùng cho cả quá trình mã hoá
		cipher.clear();				 // xóa giá trị hiện tại của cipher để cập nhật cipher mới
		/*Lấy giá trị biến plain từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm mã hoá plain bằng object e
			rồi lưu kết quả về biến cipher */
		StringSource(plain, true,
					 new StreamTransformationFilter(e,
													new StringSink(cipher)));
		// Ở CBC và ECB Mode, StreamTransformationFilter có thể thêm dữ liệu (padding) vào block cuối.
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/
	int stop_s = clock();										// Lấy mốc thời gian kết thúc mã hóa
	eTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian mã hóa có đơn vị là ms
																// Pretty print
	encodedCipher.clear();										//xóa giá trị hiện tại của encodedCipher để cập nhật cipher dạng hexa mới
	//Lấy giá trị biến cipher từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedCipher bằng hàm StringSink
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(encodedCipher)) // HexEncoder
	);												// StringSource
	wencodedCipher = utf8_to_wstring(encodedCipher);
	//cout << "cipher text: " << encoded << endl;
	return eTime;
}
double decTimeECB()
{
	int start_s = clock(); // Lấy mốc thời gian bắt đầu giải mã
	double decTime;		   //Khai báo biến lưu thời gian giải mã
	try
	{
		ECB_Mode<DES>::Decryption d; // khai báo biến d thuộc struct ECB_Mode<DES>::Decryption
									 // dùng để thực hiện các hàm giải mã ECB mode
		d.SetKey(key, key.size());	 // e gọi hàm SetKey với tham số là biến key dùng cho cả quá trình giải mã
		recovered.clear();
		// StreamTransformationFilter xoá bỏ dữ liệu thêm vào block cuối (padding)
		/*Lấy giá trị biến cipher từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm giải mã cipher bằng object d
			rồi lưu kết quả về biến recovered */
		StringSource s(cipher, true,
					   new StreamTransformationFilter(d,
													  new StringSink(recovered)) // StreamTransformationFilter
		);																		 // StringSource
	}
	catch (const CryptoPP::Exception &e) // Quá trình giải mã thực hiện không thành công
	{
		cerr << e.what() << endl;
		exit(1);
	}
	int stop_s = clock();										  // Lấy mốc thời gian kết thúc giải mã
	decTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian giải mã có đơn vị là ms
	return decTime;
	/*********************************\
	\*********************************/
}
void ECBMode(string plain)
{
	prng.GenerateBlock(key, key.size()); // Random key có độ dài 8-byte
	// Pretty print key
	encodedKey.clear(); // xóa giá trị hiện tại của key để cập nhật key mới
	//Lấy giá trị biến key từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedKey bằng hàm StringSink
	StringSource(key, key.size(), true,
				 new HexEncoder(
					 new StringSink(encodedKey)) // HexEncoder
	);											 // StringSource
	wencodedKey = utf8_to_wstring(encodedKey);
	double total = 0, avgEncTime;	// Biến total lưu tổng thời gian chạy 10000 rounds encryption , avgEncTime lưu thời gian trung bình mỗi round
	int a = 1; 	// Biến đếm số round
	while (a < 10001)
	{
		total = total + encTimeECB(plain);	// cộng thời gian chạy từng round vào total
		a = a + 1;	// Chuyển sang round tiếp theo
	}
	avgEncTime = total / 10000; // Thời gian trung bình sau 10000 rounds
	wcout << L"Key: " << wencodedKey << endl;
	wcout << L"Ciphertext: " << wencodedCipher << endl;
	wcout << L"Total Encryption time (10000 rounds): " << total << " ms\n";
	wcout << L"Encryption time: " << avgEncTime << " ms\n";

	
	double total2 = 0, avgDecTime;	// Biến total2 lưu tổng thời gian chạy 10000 rounds decryption , avgDecTime lưu thời gian trung bình mỗi round
	int b = 1; 	// Biến đếm số round
	while (b < 10001)
	{
		total2 = total2 + decTimeECB();	// cộng thời gian chạy từng round vào total2
		b = b + 1;	// Chuyển sang round tiếp theo
	}
	avgDecTime = total2 / 10000; 
	wstring wrecovered = utf8_to_wstring(recovered);
	wcout << L"recovered text: " << wrecovered << endl; //Xuất recovered (lưu bản mã sau giải mã)
	wcout << L"Total Decryption time (10000 rounds): " << total2 << " ms\n";
	wcout << L"Decryption time: " << avgDecTime << " ms\n"; 
}

// CBC MODE : ENCRYPTION, DECRYPTION, TIME
double encTimeCBC(string plain)
{
	prng.GenerateBlock(key, key.size()); // Random key có độ dài 8-byte
	prng.GenerateBlock(iv, sizeof(iv));	 // Random iv có độ dài 8-byte

	// Pretty print key
	encodedKey.clear(); // xóa giá trị hiện tại của key để cập nhật key mới
	//Lấy giá trị biến key từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedKey bằng hàm StringSink
	StringSource(key, key.size(), true,
				 new HexEncoder(
					 new StringSink(encodedKey)) // HexEncoder
	);											 // StringSource
	wencodedKey = utf8_to_wstring(encodedKey);
	//cout << "key: " << encoded << endl;

	// Pretty print iv
	encodedIV.clear(); // xóa giá trị hiện tại của IV để cập nhật iv mới
	//Lấy giá trị biến iv từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedIV bằng hàm StringSink
	StringSource(iv, sizeof(iv), true,
				 new HexEncoder(
					 new StringSink(encodedIV)) // HexEncoder
	);											// StringSource
	wencodedIV = utf8_to_wstring(encodedIV);
	//cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/
	int start_s = clock(); // Lấy mốc thời gian bắt đầu mã hóa
	double eTime;		   //Khai báo biến lưu thời gian mã hóa
	try
	{
		//cout << "plain text: " << plain << endl;

		CBC_Mode<DES>::Encryption e;		 // khai báo biến e thuộc struct CBC_Mode<DES>::Encryption
											 // dùng để thực hiện các hàm mã hóa CBC mode
		e.SetKeyWithIV(key, key.size(), iv); // e gọi hàm SetKeyWithIV với cặp giá trị key và iv
		cipher.clear();						 // xóa giá trị hiện tại của cipher để cập nhật cipher mới
		/*Lấy giá trị biến plain từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm mã hoá plain bằng object e
			rồi lưu kết quả về biến cipher */
		StringSource(plain, true,
					 new StreamTransformationFilter(e,
													new StringSink(cipher)));
		// Ở CBC và ECB Mode, StreamTransformationFilter có thể thêm dữ liệu (padding) vào block cuối.
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/
	int stop_s = clock();										// Lấy mốc thời gian kết thúc mã hóa
	eTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian mã hóa có đơn vị là ms
																// Pretty print
																//Lấy giá trị biến cipher từ source nhờ hàm StringSource chuyển sang
																//dạng hexadecimal rồi lưu về biến encodedCipher bằng hàm StringSink
	encodedCipher.clear();										//xóa giá trị hiện tại của encodedCipher để cập nhật cipher dạng hexa mới
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(encodedCipher)) // HexEncoder
	);												// StringSource
	wencodedCipher = utf8_to_wstring(encodedCipher);
	//cout << "cipher text: " << encoded << endl;
	return eTime;
}
double decTimeCBC()
{
	int start_s = clock(); // Lấy mốc thời gian bắt đầu giải mã
	double decTime;		   //Khai báo biến lưu thời gian giải mã
	try
	{
		CBC_Mode<DES>::Decryption d;		 // khai báo biến d thuộc struct CBC_Mode<DES>::Decryption
											 // dùng để thực hiện các hàm giải mã CBC mode
		d.SetKeyWithIV(key, key.size(), iv); // d gọi hàm SetKeyWithIV với cặp giá trị key và iv
		recovered.clear();
		// StreamTransformationFilter xoá bỏ dữ liệu thêm vào block cuối (padding)
		/*Lấy giá trị biến cipher từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm giải mã cipher bằng object d
			rồi lưu kết quả về biến recovered */
		StringSource s(cipher, true,
					   new StreamTransformationFilter(d,
													  new StringSink(recovered)) // StreamTransformationFilter
		);																		 // StringSource
	}
	catch (const CryptoPP::Exception &e) // Quá trình giải mã thực hiện không thành công
	{
		cerr << e.what() << endl;
		exit(1);
	}
	int stop_s = clock();										  // Lấy mốc thời gian kết thúc giải mã
	decTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian giải mã có đơn vị là ms
	return decTime;
	/*********************************\
	\*********************************/
}
void CBCMode(string plain)
{
	double total = 0, avgEncTime; // Biến total lưu tổng thời gian chạy 10000 rounds encryption , avgEncTime lưu thời gian trung bình mỗi round
	int a = 1; // Biến đếm số round
	while (a < 10001)
	{
		total = total + encTimeCBC(plain); // cộng thời gian chạy từng round vào total
		a = a + 1; // Chuyển sang round tiếp theo
	}
	avgEncTime = total / 10000; // Thời gian trung bình sau 10000 rounds
	wcout << L"Key: " << wencodedKey << endl;
	wcout << L"IV: " << wencodedIV << endl;
	wcout << L"Ciphertext: " << wencodedCipher << endl;
	wcout << L"Total Encryption time (10000 rounds): " << total << " ms\n";
	wcout << L"Encryption time: " << avgEncTime << " ms\n";

	double total2 = 0, avgDecTime;	// Biến total2 lưu tổng thời gian chạy 10000 rounds decryption , avgDecTime lưu thời gian trung bình mỗi round
	int b = 1; 	// Biến đếm số round
	while (b < 10001)
	{
		total2 = total2 + decTimeCBC();	// cộng thời gian chạy từng round vào total2
		b = b + 1;	// Chuyển sang round tiếp theo
	}
	avgDecTime = total2 / 10000; 
	wstring wrecovered = utf8_to_wstring(recovered);
	wcout << L"recovered text: " << wrecovered << endl; //Xuất recovered (lưu bản mã sau giải mã)
	wcout << L"Total Decryption time (10000 rounds): " << total2 << " ms\n";
	wcout << L"Decryption time: " << avgDecTime << " ms\n";
}

// OFB MODE : ENCRYPTION, DECRYPTION, TIME
double encTimeOFB(string plain)
{
	prng.GenerateBlock(key, key.size()); // Random key có độ dài 8-byte
	prng.GenerateBlock(iv, sizeof(iv));	 // Random iv có độ dài 8-byte

	// Pretty print key
	encodedKey.clear(); // xóa giá trị hiện tại của key để cập nhật key mới
	//Lấy giá trị biến key từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedKey bằng hàm StringSink
	StringSource(key, key.size(), true,
				 new HexEncoder(
					 new StringSink(encodedKey)) // HexEncoder
	);											 // StringSource
	wencodedKey = utf8_to_wstring(encodedKey);
	//cout << "key: " << encoded << endl;

	// Pretty print iv
	encodedIV.clear(); // xóa giá trị hiện tại của IV để cập nhật iv mới
	//Lấy giá trị biến iv từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedIV bằng hàm StringSink
	StringSource(iv, sizeof(iv), true,
				 new HexEncoder(
					 new StringSink(encodedIV)) // HexEncoder
	);											// StringSource
	wencodedIV = utf8_to_wstring(encodedIV);
	//cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/
	int start_s = clock(); // Lấy mốc thời gian bắt đầu mã hóa
	double eTime;		   //Khai báo biến lưu thời gian mã hóa
	try
	{
		//cout << "plain text: " << plain << endl;

		OFB_Mode<DES>::Encryption e;		 // khai báo biến e thuộc struct OFB_Mode<DES>::Encryption
											 // dùng để thực hiện các hàm mã hóa OFB mode
		e.SetKeyWithIV(key, key.size(), iv); // e gọi hàm SetKeyWithIV với cặp giá trị key và iv
		cipher.clear();						 // xóa giá trị hiện tại của cipher để cập nhật cipher mới
		/*Lấy giá trị biến plain từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm mã hoá plain bằng object e
			rồi lưu kết quả về biến cipher */
		StringSource(plain, true,
					 new StreamTransformationFilter(e,
													new StringSink(cipher)));
		// Ở CBC và ECB Mode, StreamTransformationFilter có thể thêm dữ liệu (padding) vào block cuối.
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/
	int stop_s = clock();										// Lấy mốc thời gian kết thúc mã hóa
	eTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian mã hóa có đơn vị là ms
																// Pretty print
																//Lấy giá trị biến cipher từ source nhờ hàm StringSource chuyển sang
																//dạng hexadecimal rồi lưu về biến encodedCipher bằng hàm StringSink
	encodedCipher.clear();										//xóa giá trị hiện tại của encodedCipher để cập nhật cipher dạng hexa mới
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(encodedCipher)) // HexEncoder
	);												// StringSource
	wencodedCipher = utf8_to_wstring(encodedCipher);
	//cout << "cipher text: " << encoded << endl;
	return eTime;
}
double decTimeOFB()
{
	int start_s = clock(); // Lấy mốc thời gian bắt đầu giải mã
	double decTime;		   //Khai báo biến lưu thời gian giải mã
	try
	{
		OFB_Mode<DES>::Decryption d;		 // khai báo biến d thuộc struct OFB_Mode<DES>::Decryption
											 // dùng để thực hiện các hàm giải mã OFB mode
		d.SetKeyWithIV(key, key.size(), iv); // d gọi hàm SetKeyWithIV với cặp giá trị key và iv
	    recovered.clear();
		// StreamTransformationFilter xoá bỏ dữ liệu thêm vào block cuối (padding)
		/*Lấy giá trị biến cipher từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm giải mã cipher bằng object d
			rồi lưu kết quả về biến recovered */
		StringSource s(cipher, true,
					   new StreamTransformationFilter(d,
													  new StringSink(recovered)) // StreamTransformationFilter
		);																		 // StringSource
	}
	catch (const CryptoPP::Exception &e) // Quá trình giải mã thực hiện không thành công
	{
		cerr << e.what() << endl;
		exit(1);
	}
	int stop_s = clock();										  // Lấy mốc thời gian kết thúc giải mã
	decTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian giải mã có đơn vị là ms
	return decTime;
	/*********************************\
	\*********************************/
}
void OFBMode(string plain)
{
	double total = 0, avgEncTime; // Biến total lưu tổng thời gian chạy 10000 rounds encryption , avgEncTime lưu thời gian trung bình mỗi round
	int a = 1; // Biến đếm số round
	while (a < 10001)
	{
		total = total + encTimeOFB(plain); // cộng thời gian chạy từng round vào total
		a = a + 1; // Chuyển sang round tiếp theo
	}
	avgEncTime = total / 10000; // Thời gian trung bình sau 10000 rounds
	wcout << L"Key: " << wencodedKey << endl;
	wcout << L"IV: " << wencodedIV << endl;
	wcout << L"Ciphertext: " << wencodedCipher << endl;
	wcout << L"Total Encryption time (10000 rounds): " << total << " ms\n";
	wcout << L"Encryption time: " << avgEncTime << " ms\n";

	double total2 = 0, avgDecTime;	// Biến total2 lưu tổng thời gian chạy 10000 rounds decryption , avgDecTime lưu thời gian trung bình mỗi round
	int b = 1; 	// Biến đếm số round
	while (b < 10001)
	{
		total2 = total2 + decTimeOFB();	// cộng thời gian chạy từng round vào total2
		b = b + 1;	// Chuyển sang round tiếp theo
	}
	avgDecTime = total2 / 10000; 
	wstring wrecovered = utf8_to_wstring(recovered);
	wcout << L"recovered text: " << wrecovered << endl; //Xuất recovered (lưu bản mã sau giải mã)
	wcout << L"Total Decryption time (10000 rounds): " << total2 << " ms\n";
	wcout << L"Decryption time: " << avgDecTime << " ms\n";
}

// CFB MODE : ENCRYPTION, DECRYPTION, TIME
double encTimeCFB(string plain)
{
	prng.GenerateBlock(key, key.size()); // Random key có độ dài 8-byte
	prng.GenerateBlock(iv, sizeof(iv));	 // Random iv có độ dài 8-byte

	// Pretty print key
	encodedKey.clear(); // xóa giá trị hiện tại của key để cập nhật key mới
	//Lấy giá trị biến key từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedKey bằng hàm StringSink
	StringSource(key, key.size(), true,
				 new HexEncoder(
					 new StringSink(encodedKey)) // HexEncoder
	);											 // StringSource
	wencodedKey = utf8_to_wstring(encodedKey);
	//cout << "key: " << encoded << endl;

	// Pretty print iv
	encodedIV.clear(); // xóa giá trị hiện tại của IV để cập nhật iv mới
	//Lấy giá trị biến iv từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedIV bằng hàm StringSink
	StringSource(iv, sizeof(iv), true,
				 new HexEncoder(
					 new StringSink(encodedIV)) // HexEncoder
	);											// StringSource
	wencodedIV = utf8_to_wstring(encodedIV);
	//cout << "iv: " << encoded << endl;

	/*********************************\
		\*********************************/
	int start_s = clock(); // Lấy mốc thời gian bắt đầu mã hóa
	double eTime;		   //Khai báo biến lưu thời gian mã hóa
	try
	{
		//cout << "plain text: " << plain << endl;

		CFB_Mode<DES>::Encryption e;		 // khai báo biến e thuộc struct CFB_Mode<DES>::Encryption
											 // dùng để thực hiện các hàm mã hóa CFB mode
		e.SetKeyWithIV(key, key.size(), iv); // e gọi hàm SetKeyWithIV với cặp giá trị key và iv
		cipher.clear();						 // xóa giá trị hiện tại của cipher để cập nhật cipher mới
		/*Lấy giá trị biến plain từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm mã hoá plain bằng object e
			rồi lưu kết quả về biến cipher */
		StringSource(plain, true,
					 new StreamTransformationFilter(e,
													new StringSink(cipher)));
		// Ở CBC và ECB Mode, StreamTransformationFilter có thể thêm dữ liệu (padding) vào block cuối.
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
		\*********************************/
	int stop_s = clock();										// Lấy mốc thời gian kết thúc mã hóa
	eTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian mã hóa có đơn vị là ms
																// Pretty print
																//Lấy giá trị biến cipher từ source nhờ hàm StringSource chuyển sang
																//dạng hexadecimal rồi lưu về biến encodedCipher bằng hàm StringSink
	encodedCipher.clear();										//xóa giá trị hiện tại của encodedCipher để cập nhật cipher dạng hexa mới
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(encodedCipher)) // HexEncoder
	);												// StringSource
	wencodedCipher = utf8_to_wstring(encodedCipher);
	//cout << "cipher text: " << encoded << endl;
	return eTime;
}
double decTimeCFB()
{
	int start_s = clock(); // Lấy mốc thời gian bắt đầu giải mã
	double decTime;		   //Khai báo biến lưu thời gian giải mã
	try
	{
		CFB_Mode<DES>::Decryption d;		 // khai báo biến d thuộc struct CFB_Mode<DES>::Decryption
											 // dùng để thực hiện các hàm giải mã CFB mode
		d.SetKeyWithIV(key, key.size(), iv); // d gọi hàm SetKeyWithIV với cặp giá trị key và iv
		recovered.clear();
		// StreamTransformationFilter xoá bỏ dữ liệu thêm vào block cuối (padding)
		/*Lấy giá trị biến cipher từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm giải mã cipher bằng object d
			rồi lưu kết quả về biến recovered */
		StringSource s(cipher, true,
					   new StreamTransformationFilter(d,
													  new StringSink(recovered)) // StreamTransformationFilter
		);																		 // StringSource

	}
	catch (const CryptoPP::Exception &e) // Quá trình giải mã thực hiện không thành công
	{
		cerr << e.what() << endl;
		exit(1);
	}
	int stop_s = clock();										  // Lấy mốc thời gian kết thúc giải mã
	decTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian giải mã có đơn vị là ms
	return decTime;
	/*********************************\
		\*********************************/
}
void CFBMode(string plain)
{
	double total = 0, avgEncTime; // Biến total lưu tổng thời gian chạy 10000 rounds encryption , avgEncTime lưu thời gian trung bình mỗi round
	int a = 1; // Biến đếm số round
	while (a < 10001)
	{
		total = total + encTimeCFB(plain); // cộng thời gian chạy từng round vào total
		a = a + 1; // Chuyển sang round tiếp theo
	}
	avgEncTime = total / 10000; // Thời gian trung bình sau 10000 rounds
	wcout << L"Key: " << wencodedKey << endl;
	wcout << L"IV: " << wencodedIV << endl;
	wcout << L"Ciphertext: " << wencodedCipher << endl;
	wcout << L"Total Encryption time (10000 rounds): " << total << " ms\n";
	wcout << L"Encryption time: " << avgEncTime << " ms\n";

	double total2 = 0, avgDecTime;	// Biến total2 lưu tổng thời gian chạy 10000 rounds decryption , avgDecTime lưu thời gian trung bình mỗi round
	int b = 1; 	// Biến đếm số round
	while (b < 10001)
	{
		total2 = total2 + decTimeCFB();	// cộng thời gian chạy từng round vào total2
		b = b + 1;	// Chuyển sang round tiếp theo
	}
	avgDecTime = total2 / 10000; 
	wstring wrecovered = utf8_to_wstring(recovered);
	wcout << L"recovered text: " << wrecovered << endl; //Xuất recovered (lưu bản mã sau giải mã)
	wcout << L"Total Decryption time (10000 rounds): " << total2 << " ms\n";
	wcout << L"Decryption time: " << avgDecTime << " ms\n";
}

// CTR MODE : ENCRYPTION, DECRYPTION, TIME
double encTimeCTR(string plain)
{
	prng.GenerateBlock(key, key.size()); // Random key có độ dài 8-byte
	prng.GenerateBlock(iv, sizeof(iv));	 // Random iv có độ dài 8-byte

	// Pretty print key
	encodedKey.clear(); // xóa giá trị hiện tại của key để cập nhật key mới
	//Lấy giá trị biến key từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedKey bằng hàm StringSink
	StringSource(key, key.size(), true,
				 new HexEncoder(
					 new StringSink(encodedKey)) // HexEncoder
	);											 // StringSource
	wencodedKey = utf8_to_wstring(encodedKey);
	//cout << "key: " << encoded << endl;

	// Pretty print iv
	encodedIV.clear(); // xóa giá trị hiện tại của IV để cập nhật iv mới
	//Lấy giá trị biến iv từ source nhờ hàm StringSource chuyển sang
	//dạng hexadecimal rồi lưu về biến encodedIV bằng hàm StringSink
	StringSource(iv, sizeof(iv), true,
				 new HexEncoder(
					 new StringSink(encodedIV)) // HexEncoder
	);											// StringSource
	wencodedIV = utf8_to_wstring(encodedIV);
	//cout << "iv: " << encoded << endl;

	/*********************************\
		\*********************************/
	int start_s = clock(); // Lấy mốc thời gian bắt đầu mã hóa
	double eTime;		   //Khai báo biến lưu thời gian mã hóa
	try
	{
		//cout << "plain text: " << plain << endl;

		CTR_Mode<DES>::Encryption e;		 // khai báo biến e thuộc struct CTR_Mode<DES>::Encryption
											 // dùng để thực hiện các hàm mã hóa CTR mode
		e.SetKeyWithIV(key, key.size(), iv); // e gọi hàm SetKeyWithIV với cặp giá trị key và iv
		cipher.clear();						 // xóa giá trị hiện tại của cipher để cập nhật cipher mới
		/*Lấy giá trị biến plain từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm mã hoá plain bằng object e
			rồi lưu kết quả về biến cipher */
		StringSource(plain, true,
					 new StreamTransformationFilter(e,
													new StringSink(cipher)));
		// Ở CBC và ECB Mode, StreamTransformationFilter có thể thêm dữ liệu (padding) vào block cuối.
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/
	int stop_s = clock();										// Lấy mốc thời gian kết thúc mã hóa
	eTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian mã hóa có đơn vị là ms
																// Pretty print
																//Lấy giá trị biến cipher từ source nhờ hàm StringSource chuyển sang
																//dạng hexadecimal rồi lưu về biến encodedCipher bằng hàm StringSink
	encodedCipher.clear();										//xóa giá trị hiện tại của encodedCipher để cập nhật cipher dạng hexa mới
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(encodedCipher)) // HexEncoder
	);												// StringSource
	wencodedCipher = utf8_to_wstring(encodedCipher);
	//cout << "cipher text: " << encoded << endl;
	return eTime;
}
double decTimeCTR()
{
	int start_s = clock(); // Lấy mốc thời gian bắt đầu giải mã
	double decTime;		   //Khai báo biến lưu thời gian giải mã
	try
	{
		CTR_Mode<DES>::Decryption d;		 // khai báo biến d thuộc struct CTR_Mode<DES>::Decryption
											 // dùng để thực hiện các hàm giải mã CTR mode
		d.SetKeyWithIV(key, key.size(), iv); // d gọi hàm SetKeyWithIV với cặp giá trị key và iv
		recovered.clear();
		// StreamTransformationFilter xoá bỏ dữ liệu thêm vào block cuối (padding)
		/*Lấy giá trị biến cipher từ source nhờ hàm StringSource 
			đi qua hàm StreamTransformationFilter nhằm giải mã cipher bằng object d
			rồi lưu kết quả về biến recovered */
		StringSource s(cipher, true,
					   new StreamTransformationFilter(d,
													  new StringSink(recovered)) // StreamTransformationFilter
		);																		 // StringSource
	}
	catch (const CryptoPP::Exception &e) // Quá trình giải mã thực hiện không thành công
	{
		cerr << e.what() << endl;
		exit(1);
	}
	int stop_s = clock();										  // Lấy mốc thời gian kết thúc giải mã
	decTime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000; // Lấy thời gian giải mã có đơn vị là ms
	return decTime;
	/*********************************\
		\*********************************/
}
void CTRMode(string plain)
{
	double total = 0, avgEncTime; // Biến total lưu tổng thời gian chạy 10000 rounds encryption , avgEncTime lưu thời gian trung bình mỗi round
	int a = 1; // Biến đếm số round
	while (a < 10001)
	{
		total = total + encTimeCTR(plain); // cộng thời gian chạy từng round vào total
		a = a + 1; // Chuyển sang round tiếp theo
	}
	avgEncTime = total / 10000; // Thời gian trung bình sau 10000 rounds
	wcout << L"Key: " << wencodedKey << endl;
	wcout << L"IV: " << wencodedIV << endl;
	wcout << L"Ciphertext: " << wencodedCipher << endl;
	wcout << L"Total Encryption time (10000 rounds): " << total << " ms\n";
	wcout << L"Encryption time: " << avgEncTime << " ms\n";

	double total2 = 0, avgDecTime;	// Biến total2 lưu tổng thời gian chạy 10000 rounds decryption , avgDecTime lưu thời gian trung bình mỗi round
	int b = 1; 	// Biến đếm số round
	while (b < 10001)
	{
		total2 = total2 + decTimeCTR();	// cộng thời gian chạy từng round vào total2
		b = b + 1;	// Chuyển sang round tiếp theo
	}
	avgDecTime = total2 / 10000; 
	wstring wrecovered = utf8_to_wstring(recovered);
	wcout << L"recovered text: " << wrecovered << endl; //Xuất recovered (lưu bản mã sau giải mã)
	wcout << L"Total Decryption time (10000 rounds): " << total2 << " ms\n";
	wcout << L"Decryption time: " << avgDecTime << " ms\n";
}

int main(int argc, char *argv[])
{
	_setmode(_fileno(stdout), _O_WTEXT); //needed for output
	_setmode(_fileno(stdin), _O_WTEXT);	 //needed for input

	wcout << L"Type plaintext here: ";
	wstring plaintext;						   // Sử dụng wstring để hỗ trợ tiếng Việt 
	getline(wcin, plaintext);				   // Nhâp bản rõ(plaintext)
	string plain = wstring_to_utf8(plaintext); // Khởi tạo plain lưu dạng utf8 từ wstring plaintext
	wcout << L"====================\n";

	/*********************************\
	\*********************************/

	//Mục lục chọn mode dùng cho block cipher
	wcout << L"Choose a mode of operation:\n";
	wcout << L"\t1. CBC Mode\n";
	wcout << L"\t2. ECB Mode\n";
	wcout << L"\t3. OFB Mode\n";
	wcout << L"\t4. CFB Mode\n";
	wcout << L"\t5.  Mode\n";
	wcout << L"\t6. CTR Mode\n";
	wcout << L"====================\n";
	wcout << L"Mode: ";

	int mode;
	wcin >> mode; // Nhập số tương ứng với mode mình chọn
	wcout << L"====================\n";
	wcout << L"plain text: " << plaintext << endl; // in ra plaintext
	switch (mode)
	{
	case 1: //CBC Mode
		CBCMode(plain);
		break;
	case 2: //ECB Mode
		ECBMode(plain);
		break;
	case 3: //OFB Mode
		OFBMode(plain);
		break;
	case 4: //CFB Mode
		CFBMode(plain);
		break;
	case 5: //CBC-CTS Mode
		(plain);
		break;
	case 6: //CTR Mode
		CTRMode(plain);
		break;
	}
	return 0;
}
