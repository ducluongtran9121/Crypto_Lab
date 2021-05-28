// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <windows.h>

#include <iostream>
using namespace std;

#include <string>
using std::string;

#include <ctime>

#include <codecvt>
#include <locale>
// use convert string <-> wstring

#include <io.h>
#include <fcntl.h>
// use setmode

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::byte;
using CryptoPP::Exception;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;
#include "cryptopp/xts.h"
using CryptoPP::XTS;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "assert.h"

// convert string to wstring
std::wstring string_to_wstring(const std::string &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to string
std::string wstring_to_string(const std::wstring &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

// Khai báo các hàm của các DES mode of operation 
void DES_ECB_MODE(wstring, wstring);
void DES_CBC_MODE(wstring, wstring, wstring);
void DES_OFB_MODE(wstring, wstring, wstring);
void DES_CFB_MODE(wstring, wstring, wstring);
void DES_CTR_MODE(wstring, wstring, wstring);
void DES_XTS_MODE(wstring, wstring, wstring);

int main(int argc, char *argv[])
{
    //set mode để hỗ trợ nhập và xuất Tiếng Việt
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);

    wstring enter; // tránh lỗi getline
    int mode; // Chọn mode muốn thực hiện DES
    wcout << L"Choose a mode of operation:\n";
    wcout << L"\t0. ECB Mode\n";
    wcout << L"\t1. CBC Mode\n";
    wcout << L"\t2. OFB Mode\n";
    wcout << L"\t3. CFB Mode\n";
    wcout << L"\t4. CTR Mode\n";
    wcout << L"====================\n";
    wcout << L"Mode: ";
    wcin >> mode;
    getline(wcin, enter);

    wcout << L"Enter plaintext:  ";
    wstring plain; // plaintext có hỗ trợ tiếng việt
    wcin.ignore();
    getline(wcin, plain);
    
    wstring key; // key sử dụng cho DES
    int type_key; // Chọn cách input key
    wcout << L"Choose type of key input:\n";
    wcout << L"\t1. Random key\n";  // Key random
    wcout << L"\t2. From file \n";  // Lấy key từ file
    wcout << L"\t3. From screen\n"; // Nhập từ màn hình terminal
    wcout << L"Type of key input: ";
    wcin >> type_key;
    getline(wcin, enter);
    switch (type_key)
    {
        case 1:
            key = L"Random"; 
            break;
        case 2:
            key = L"File";
            break;
        case 3:
            wcout << L"Enter key (8 bytes): ";
            wcin.ignore();
            getline(wcin, key);
            break;
        default:
            key = L"Random";
            break;
    }

    wstring iv;
    if (mode != 0) // Khác ECB mode mới dùng iv
    {
        int type_iv; // Chọn cách nhập iv 
        wcout << L"Choose type of iv input:\n";
        wcout << L"\t1. Random iv\n";
        wcout << L"\t2. From file\n";
        wcout << L"\t3. From screen\n";
        wcout << L"Type of iv input: ";
        wcin >> type_iv;
        getline(wcin, enter);
        switch (type_iv)
        {
        case 1:
            iv = L"Random";
            break;
        case 2:
            iv = L"File";
            break;
        case 3:
            wcout << L"Enter iv (8 bytes): ";
            wcin.ignore();
            getline(wcin, iv);
            break;
        default:
            iv = L"Random";
            break;
        }
    }

    // Switch case mode
    switch (mode)
    {
        case 0:
            wcout << L"====DES ECB MODE====" << endl;
            DES_ECB_MODE(plain, key);
            break;

        case 1:
            wcout << L"====DES CBC MODE===="<<endl;
            DES_CBC_MODE(plain, key, iv);
            break;
        
        case 2:
            wcout << L"====DES OFB MODE===="<<endl;
            DES_OFB_MODE(plain, key, iv);
            break;

        case 3:
            wcout << L"====DES CFB MODE===="<<endl;
            DES_CFB_MODE(plain, key, iv);
            break;

        case 4:
            wcout<<L"====DES CTR MODE===="<<endl;
            DES_CTR_MODE(plain, key, iv);
            break;

        default:
            wcout << L"====DES ECB MODE====" << endl;
            DES_ECB_MODE(plain, iv);
            break;
    }
    return 0;
}

void DES_ECB_MODE(wstring input, wstring WKey)
{
    AutoSeededRandomPool prng;        // khai báo đối tượng prng để sử dụng cho random block key, iv
    byte key[DES::DEFAULT_KEYLENGTH]; // khởi tạo mảng byte key[8]

    if (WKey == L"Random") //trường hợp input bằng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key bằng GenerateBlock
    }
    else if (WKey == L"File") // trường hợp input từ File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(8); // Pump first 8 bytes
    }
    else // trường hợp input từ screen
    {
        /* convert WKey(wstring) sang SKey(string) để xử lý */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(8); // Pump first 8 bytes
    }

    if (WKey != L"File") //DES_key.key sẽ lưu key được nhập từ screen hoặc random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }

    string plain = wstring_to_string(input); // convert wtring tiếng việt sang string dạng utf8
    string cipher, encoded, recovered;       //khai báo đầu vào

    // Pretty print key
    encoded.clear();                     // xóa giá trị hiện tại của encoded
    StringSource(key, sizeof(key), true, // chuyển mảng byte "key" sang chuỗi "encoded" dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xuất wencoded bằng wcout vì 2 dòng khai báo ở hàm main

    ECB_Mode<DES>::Encryption e; //khai báo đối tượng encryption e với mode ECB
    try                          // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        wcout << L"plain text: " << input << endl; // xuất plaintext
        e.SetKey(key, sizeof(key));  //e gọi hàm tạo key với mảng key

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true, //chuyển đổi chuỗi plain qua luồng "e" thành chuỗi cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //nếu có lỗi, thông báo và thoát chương trình
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xoá giá trị hiện tại của encode
    StringSource(cipher, true, // chuyển chuỗi cipher thành chuỗi encoded dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuyển string encoded sang wstring wencoded3 đê xuất bằng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xuất cịphertext
    
    // Đọc key từ DES_key.key dùng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(8); // Pump first 8 bytes

    ECB_Mode<DES>::Decryption d; // khởi tạo đối tượng decryption "d" với mode ECB
    try                          // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        d.SetKey(key, sizeof(key));  // đối tượng d gọi hàm tạo key với mảng key

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true, // chuyển chuỗi cipher bằng luồng "d" sang chuỗi recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuyển đổi chuỗi utf8 "recovered" được decryption thành wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xuất chuỗi wstring recov
    }
    catch (const CryptoPP::Exception &e) // nếu phần code trong đoạn try có lỗi thực hiện phần code trong đoạn catch
    {
        cerr << e.what() << endl; // báo lỗi và dừng chương trình
        exit(1);
    }

    double encTime = 0; //tổng thời gian Encryption
    double decTime = 0; //tổng thời gian Decryption
    double total = 0;   //tổng thời gian Mode
    int round = 1;
    while(round < 10001) // thực hiện đo thời gian encryption 10000 lần
    {
        //ENCRYPTION
        int enc_start = clock();  // thời gian bắt đầu thực hiên encryption
        int mode_start = clock(); // thời gian bắt đầu của mode
        e.SetKey(key, sizeof(key));
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // thời gian kết thúc encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // tổng hợp thời gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // thời gian bắt đầu thực hiện decryption
        d.SetKey(key, sizeof(key));
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered)) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // thời gian kết thúc decryption
        int mode_end = clock();                                                   // thời gian kết thúc mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian mode
        round++;                                                                  // round tiếp theo
    }

    wcout << L"=======================================================\n";
    // xuất thời gian thực hiện 10000 vòng và 1 vòng
    wcout << L"Total time for 10000 rounds:\n\tMode ECB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode ECB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_CBC_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai báo đối tượng prng để sử dụng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // khởi tạo mảng byte key[8]

    if (WKey == L"Random") //trường hợp input bằng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key bằng GenerateBlock
    }
    else if (WKey == L"File") // trường hợp input từ File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // trường hợp input từ screen
    {
        /* convert WKey(wstring) sang SKey(string) để xử lý */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key sẽ lưu key được nhập từ screen hoặc random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //khởi tạo mảng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // tạo block key random
	else if(wIV == L"File") // IV input từ file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input từ screen
	{
		/* convert WKey(wstring) sang SKey(string) để xử lý */
		string sIV(wIV.begin(), wIV.end()); //nếu convert string không có tiếng việt dùng cách này cũng được

		/* Reading key from  input screen*/
		StringSource sss(sIV, false);

		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(iv, sizeof(iv));

		/*Copy data to key*/ 
		sss.Detach(new Redirector(copykey));
		sss.Pump(16);  // Pump first 16 bytes
	}

	if(wIV != L"File") 
	{
		//Write key to file DES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "DES_iv.key"));
	}
    string plain = wstring_to_string(input); // convert wtring tiếng việt sang string dạng utf8
    string cipher, encoded, recovered;       //khai báo đầu vào

    // Pretty print key
    encoded.clear();                     // xóa giá trị hiện tại của encoded
    StringSource(key, sizeof(key), true, // chuyển mảng byte "key" sang chuỗi "encoded" dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xuất wencoded bằng wcout vì 2 dòng khai báo ở hàm main

    // Pretty print iv
	encoded.clear(); // xóa giá trị hiện tại của encoded
	StringSource(iv, sizeof(iv), true, //chuyển mảng byte "iv" sang chuỗi "encoded" dưới dạng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xuất wencoded2 bằng wcout vì 2 dòng khai báo ở hàm main
    CBC_Mode<DES>::Encryption e; //khai báo đối tượng encryption e với mode CBC
    try                          // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        wcout << L"plain text: " << input << endl; // xuất plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e gọi hàm tạo key với 2 mảng key và iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuyển đổi chuỗi plain qua luồng "e" thành chuỗi cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //nếu có lỗi, thông báo và thoát chương trình
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xoá giá trị hiện tại của encode
    StringSource(cipher, true, // chuyển chuỗi cipher thành chuỗi encoded dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuyển string encoded sang wstring wencoded3 để xuất bằng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xuất ciphertext 
    
    // Đọc key từ DES_key.key dùng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // Đọc iv từ DES_iv.key dùng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CBC_Mode<DES>::Decryption d; // khởi tạo đối tượng decryption "d" với mode CBC
    try  // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// đối tượng d gọi hàm tạo key với 2 mảng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuyển chuỗi cipher bằng luồng "d" sang chuỗi recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuyển đổi chuỗi utf8 "recovered" được decryption thành wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xuất chuỗi wstring recov
    }
    catch (const CryptoPP::Exception &e) // nếu phần code trong đoạn try có lỗi thực hiện phần code trong đoạn catch
    {
        cerr << e.what() << endl; // báo lỗi và dừng chương trình
        exit(1);
    }

    double encTime = 0; //tổng thời gian Encryption
    double decTime = 0; //tổng thời gian Decryption
    double total = 0;   //tổng thời gian Mode
    int round = 1;
    while(round < 10001) // thực hiện đo thời gian encryption 10000 lần
    {
        //ENCRYPTION
        int enc_start = clock();  // thời gian bắt đầu thực hiên encryption
        int mode_start = clock(); // thời gian bắt đầu của mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // thời gian kết thúc encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // tổng hợp thời gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // thời gian bắt đầu thực hiện decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered)) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // thời gian kết thúc decryption
        int mode_end = clock();                                                   // thời gian kết thúc mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian mode
        round++;                                                                  // round tiếp theo
    }

    wcout << L"=======================================================\n";
    // xuất thời gian thực hiện 10000 vòng và 1 vòng
    wcout << L"Total time for 10000 rounds:\n\tMode CBC: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CBC: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_OFB_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai báo đối tượng prng để sử dụng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // khởi tạo mảng byte key[8]

    if (WKey == L"Random") //trường hợp input bằng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key bằng GenerateBlock
    }
    else if (WKey == L"File") // trường hợp input từ File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // trường hợp input từ screen
    {
        /* convert WKey(wstring) sang SKey(string) để xử lý */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key sẽ lưu key được nhập từ screen hoặc random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //khởi tạo mảng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // tạo block key random
	else if(wIV == L"File") // IV input từ file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input từ screen
	{
		/* convert WKey(wstring) sang SKey(string) để xử lý */
		string sIV(wIV.begin(), wIV.end()); //nếu convert string không có tiếng việt dùng cách này cũng được

		/* Reading key from  input screen*/
		StringSource sss(sIV, false);

		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(iv, sizeof(iv));

		/*Copy data to key*/ 
		sss.Detach(new Redirector(copykey));
		sss.Pump(16);  // Pump first 16 bytes
	}

	if(wIV != L"File") 
	{
		//Write key to file DES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "DES_iv.key"));
	}
    string plain = wstring_to_string(input); // convert wtring tiếng việt sang string dạng utf8
    string cipher, encoded, recovered;       //khai báo đầu vào

    // Pretty print key
    encoded.clear();                     // xóa giá trị hiện tại của encoded
    StringSource(key, sizeof(key), true, // chuyển mảng byte "key" sang chuỗi "encoded" dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xuất wencoded bằng wcout vì 2 dòng khai báo ở hàm main

    // Pretty print iv
	encoded.clear(); // xóa giá trị hiện tại của encoded
	StringSource(iv, sizeof(iv), true, //chuyển mảng byte "iv" sang chuỗi "encoded" dưới dạng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xuất wencoded2 bằng wcout vì 2 dòng khai báo ở hàm main
    OFB_Mode<DES>::Encryption e; //khai báo đối tượng encryption e với mode OFB
    try                          // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        wcout << L"plain text: " << input << endl; // xuất plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e gọi hàm tạo key với 2 mảng key và iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuyển đổi chuỗi plain qua luồng "e" thành chuỗi cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //nếu có lỗi, thông báo và thoát chương trình
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xoá giá trị hiện tại của encode
    StringSource(cipher, true, // chuyển chuỗi cipher thành chuỗi encoded dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuyển string encoded sang wstring wencoded3 để xuất bằng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xuất ciphertext 
    
    // Đọc key từ DES_key.key dùng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // Đọc iv từ DES_iv.key dùng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    OFB_Mode<DES>::Decryption d; // khởi tạo đối tượng decryption "d" với mode OFB
    try  // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// đối tượng d gọi hàm tạo key với 2 mảng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuyển chuỗi cipher bằng luồng "d" sang chuỗi recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuyển đổi chuỗi utf8 "recovered" được decryption thành wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xuất chuỗi wstring recov
    }
    catch (const CryptoPP::Exception &e) // nếu phần code trong đoạn try có lỗi thực hiện phần code trong đoạn catch
    {
        cerr << e.what() << endl; // báo lỗi và dừng chương trình
        exit(1);
    }

    double encTime = 0; //tổng thời gian Encryption
    double decTime = 0; //tổng thời gian Decryption
    double total = 0;   //tổng thời gian Mode
    int round = 1;
    while(round < 10001) // thực hiện đo thời gian encryption 10000 lần
    {
        //ENCRYPTION
        int enc_start = clock();  // thời gian bắt đầu thực hiên encryption
        int mode_start = clock(); // thời gian bắt đầu của mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // thời gian kết thúc encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // tổng hợp thời gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // thời gian bắt đầu thực hiện decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // thời gian kết thúc decryption
        int mode_end = clock();                                                   // thời gian kết thúc mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian mode
        round++;                                                                  // round tiếp theo
    }

    wcout << L"=======================================================\n";
    // xuất thời gian thực hiện 10000 vòng và 1 vòng
    wcout << L"Total time for 10000 rounds:\n\tMode OFB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode OFB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_CFB_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai báo đối tượng prng để sử dụng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // khởi tạo mảng byte key[8]

    if (WKey == L"Random") //trường hợp input bằng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key bằng GenerateBlock
    }
    else if (WKey == L"File") // trường hợp input từ File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // trường hợp input từ screen
    {
        /* convert WKey(wstring) sang SKey(string) để xử lý */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key sẽ lưu key được nhập từ screen hoặc random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //khởi tạo mảng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // tạo block key random
	else if(wIV == L"File") // IV input từ file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input từ screen
	{
		/* convert WKey(wstring) sang SKey(string) để xử lý */
		string sIV(wIV.begin(), wIV.end()); //nếu convert string không có tiếng việt dùng cách này cũng được

		/* Reading key from  input screen*/
		StringSource sss(sIV, false);

		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(iv, sizeof(iv));

		/*Copy data to key*/ 
		sss.Detach(new Redirector(copykey));
		sss.Pump(16);  // Pump first 16 bytes
	}

	if(wIV != L"File") 
	{
		//Write key to file DES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "DES_iv.key"));
	}
    string plain = wstring_to_string(input); // convert wtring tiếng việt sang string dạng utf8
    string cipher, encoded, recovered;       //khai báo đầu vào

    // Pretty print key
    encoded.clear();                     // xóa giá trị hiện tại của encoded
    StringSource(key, sizeof(key), true, // chuyển mảng byte "key" sang chuỗi "encoded" dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xuất wencoded bằng wcout vì 2 dòng khai báo ở hàm main

    // Pretty print iv
	encoded.clear(); // xóa giá trị hiện tại của encoded
	StringSource(iv, sizeof(iv), true, //chuyển mảng byte "iv" sang chuỗi "encoded" dưới dạng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xuất wencoded2 bằng wcout vì 2 dòng khai báo ở hàm main
    CFB_Mode<DES>::Encryption e; //khai báo đối tượng encryption e với mode CFB
    try                          // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        wcout << L"plain text: " << input << endl; // xuất plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e gọi hàm tạo key với 2 mảng key và iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuyển đổi chuỗi plain qua luồng "e" thành chuỗi cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //nếu có lỗi, thông báo và thoát chương trình
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xoá giá trị hiện tại của encode
    StringSource(cipher, true, // chuyển chuỗi cipher thành chuỗi encoded dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuyển string encoded sang wstring wencoded3 để xuất bằng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xuất ciphertext 
    
    // Đọc key từ DES_key.key dùng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // Đọc iv từ DES_iv.key dùng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CFB_Mode<DES>::Decryption d; // khởi tạo đối tượng decryption "d" với mode CFB
    try  // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// đối tượng d gọi hàm tạo key với 2 mảng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuyển chuỗi cipher bằng luồng "d" sang chuỗi recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuyển đổi chuỗi utf8 "recovered" được decryption thành wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xuất chuỗi wstring recov
    }
    catch (const CryptoPP::Exception &e) // nếu phần code trong đoạn try có lỗi thực hiện phần code trong đoạn catch
    {
        cerr << e.what() << endl; // báo lỗi và dừng chương trình
        exit(1);
    }

    double encTime = 0; //tổng thời gian Encryption
    double decTime = 0; //tổng thời gian Decryption
    double total = 0;   //tổng thời gian Mode
    int round = 1;
    while(round < 10001) // thực hiện đo thời gian encryption 10000 lần
    {
        //ENCRYPTION
        int enc_start = clock();  // thời gian bắt đầu thực hiên encryption
        int mode_start = clock(); // thời gian bắt đầu của mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // thời gian kết thúc encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // tổng hợp thời gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // thời gian bắt đầu thực hiện decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // thời gian kết thúc decryption
        int mode_end = clock();                                                   // thời gian kết thúc mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian mode
        round++;                                                                  // round tiếp theo
    }

    wcout << L"=======================================================\n";
    // xuất thời gian thực hiện 10000 vòng và 1 vòng
    wcout << L"Total time for 10000 rounds:\n\tMode CFB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CFB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_CTR_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai báo đối tượng prng để sử dụng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // khởi tạo mảng byte key[8]

    if (WKey == L"Random") //trường hợp input bằng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key bằng GenerateBlock
    }
    else if (WKey == L"File") // trường hợp input từ File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // trường hợp input từ screen
    {
        /* convert WKey(wstring) sang SKey(string) để xử lý */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key sẽ lưu key được nhập từ screen hoặc random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //khởi tạo mảng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // tạo block key random
	else if(wIV == L"File") // IV input từ file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input từ screen
	{
		/* convert WKey(wstring) sang SKey(string) để xử lý */
		string sIV(wIV.begin(), wIV.end()); //nếu convert string không có tiếng việt dùng cách này cũng được

		/* Reading key from  input screen*/
		StringSource sss(sIV, false);

		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(iv, sizeof(iv));

		/*Copy data to key*/ 
		sss.Detach(new Redirector(copykey));
		sss.Pump(16);  // Pump first 16 bytes
	}

	if(wIV != L"File") 
	{
		//Write key to file DES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "DES_iv.key"));
	}
    string plain = wstring_to_string(input); // convert wtring tiếng việt sang string dạng utf8
    string cipher, encoded, recovered;       //khai báo đầu vào

    // Pretty print key
    encoded.clear();                     // xóa giá trị hiện tại của encoded
    StringSource(key, sizeof(key), true, // chuyển mảng byte "key" sang chuỗi "encoded" dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xuất wencoded bằng wcout vì 2 dòng khai báo ở hàm main

    // Pretty print iv
	encoded.clear(); // xóa giá trị hiện tại của encoded
	StringSource(iv, sizeof(iv), true, //chuyển mảng byte "iv" sang chuỗi "encoded" dưới dạng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xuất wencoded2 bằng wcout vì 2 dòng khai báo ở hàm main
    CTR_Mode<DES>::Encryption e; //khai báo đối tượng encryption e với mode CTR
    try                          // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        wcout << L"plain text: " << input << endl; // xuất plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e gọi hàm tạo key với 2 mảng key và iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuyển đổi chuỗi plain qua luồng "e" thành chuỗi cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //nếu có lỗi, thông báo và thoát chương trình
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xoá giá trị hiện tại của encode
    StringSource(cipher, true, // chuyển chuỗi cipher thành chuỗi encoded dưới dạng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuyển string encoded sang wstring wencoded3 để xuất bằng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xuất ciphertext 
    
    // Đọc key từ DES_key.key dùng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // Đọc iv từ DES_iv.key dùng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CTR_Mode<DES>::Decryption d; // khởi tạo đối tượng decryption "d" với mode CTR
    try  // thực hiện khối lệch dưới, nếu không được báo lỗi trong phần catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// đối tượng d gọi hàm tạo key với 2 mảng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuyển chuỗi cipher bằng luồng "d" sang chuỗi recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuyển đổi chuỗi utf8 "recovered" được decryption thành wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xuất chuỗi wstring recov
    }
    catch (const CryptoPP::Exception &e) // nếu phần code trong đoạn try có lỗi thực hiện phần code trong đoạn catch
    {
        cerr << e.what() << endl; // báo lỗi và dừng chương trình
        exit(1);
    }

    double encTime = 0; //tổng thời gian Encryption
    double decTime = 0; //tổng thời gian Decryption
    double total = 0;   //tổng thời gian Mode
    int round = 1;
    while(round < 10001) // thực hiện đo thời gian mode chạy 10000 lần
    {
        //ENCRYPTION
        int enc_start = clock();  // thời gian bắt đầu thực hiên encryption
        int mode_start = clock(); // thời gian bắt đầu của mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // thời gian kết thúc encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // tổng hợp thời gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // thời gian bắt đầu thực hiện decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // thời gian kết thúc decryption
        int mode_end = clock();                                                   // thời gian kết thúc mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // tổng hợp thời gian mode
        round++;                                                                  // round tiếp theo
    }

    wcout << L"=======================================================\n";
    // xuất thời gian thực hiện 10000 vòng và 1 vòng
    wcout << L"Total time for 10000 rounds:\n\tMode CTR: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CTR: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}

