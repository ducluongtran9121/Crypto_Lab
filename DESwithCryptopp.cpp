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

// Khai b??o c??c h??m c???a c??c DES mode of operation 
void DES_ECB_MODE(wstring, wstring);
void DES_CBC_MODE(wstring, wstring, wstring);
void DES_OFB_MODE(wstring, wstring, wstring);
void DES_CFB_MODE(wstring, wstring, wstring);
void DES_CTR_MODE(wstring, wstring, wstring);
void DES_XTS_MODE(wstring, wstring, wstring);

int main(int argc, char *argv[])
{
    //set mode ????? h??? tr??? nh???p v?? xu???t Ti???ng Vi???t
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);

    wstring enter; // tr??nh l???i getline
    int mode; // Ch???n mode mu???n th???c hi???n DES
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
    wstring plain; // plaintext c?? h??? tr??? ti???ng vi???t
    wcin.ignore();
    getline(wcin, plain);
    
    wstring key; // key s??? d???ng cho DES
    int type_key; // Ch???n c??ch input key
    wcout << L"Choose type of key input:\n";
    wcout << L"\t1. Random key\n";  // Key random
    wcout << L"\t2. From file \n";  // L???y key t??? file
    wcout << L"\t3. From screen\n"; // Nh???p t??? m??n h??nh terminal
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
    if (mode != 0) // Kh??c ECB mode m???i d??ng iv
    {
        int type_iv; // Ch???n c??ch nh???p iv 
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
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    byte key[DES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[8]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(8); // Pump first 8 bytes
    }
    else // tr?????ng h???p input t??? screen
    {
        /* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(8); // Pump first 8 bytes
    }

    if (WKey != L"File") //DES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }

    string plain = wstring_to_string(input); // convert wtring ti???ng vi???t sang string d???ng utf8
    string cipher, encoded, recovered;       //khai b??o ?????u v??o

    // Pretty print key
    encoded.clear();                     // x??a gi?? tr??? hi???n t???i c???a encoded
    StringSource(key, sizeof(key), true, // chuy???n m???ng byte "key" sang chu???i "encoded" d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xu???t wencoded b???ng wcout v?? 2 d??ng khai b??o ??? h??m main

    ECB_Mode<DES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode ECB
    try                          // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        wcout << L"plain text: " << input << endl; // xu???t plaintext
        e.SetKey(key, sizeof(key));  //e g???i h??m t???o key v???i m???ng key

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true, //chuy???n ?????i chu???i plain qua lu???ng "e" th??nh chu???i cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //n???u c?? l???i, th??ng b??o v?? tho??t ch????ng tr??nh
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xo?? gi?? tr??? hi???n t???i c???a encode
    StringSource(cipher, true, // chuy???n chu???i cipher th??nh chu???i encoded d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuy???n string encoded sang wstring wencoded3 ???? xu???t b???ng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xu???t c???phertext
    
    // ?????c key t??? DES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(8); // Pump first 8 bytes

    ECB_Mode<DES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode ECB
    try                          // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        d.SetKey(key, sizeof(key));  // ?????i t?????ng d g???i h??m t???o key v???i m???ng key

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true, // chuy???n chu???i cipher b???ng lu???ng "d" sang chu???i recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuy???n ?????i chu???i utf8 "recovered" ???????c decryption th??nh wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xu???t chu???i wstring recov
    }
    catch (const CryptoPP::Exception &e) // n???u ph???n code trong ??o???n try c?? l???i th???c hi???n ph???n code trong ??o???n catch
    {
        cerr << e.what() << endl; // b??o l???i v?? d???ng ch????ng tr??nh
        exit(1);
    }

    double encTime = 0; //t???ng th???i gian Encryption
    double decTime = 0; //t???ng th???i gian Decryption
    double total = 0;   //t???ng th???i gian Mode
    int round = 1;
    while(round < 10001) // th???c hi???n ??o th???i gian encryption 10000 l???n
    {
        //ENCRYPTION
        int enc_start = clock();  // th???i gian b???t ?????u th???c hi??n encryption
        int mode_start = clock(); // th???i gian b???t ?????u c???a mode
        e.SetKey(key, sizeof(key));
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // th???i gian k???t th??c encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // t???ng h???p th???i gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // th???i gian b???t ?????u th???c hi???n decryption
        d.SetKey(key, sizeof(key));
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered)) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // th???i gian k???t th??c decryption
        int mode_end = clock();                                                   // th???i gian k???t th??c mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian mode
        round++;                                                                  // round ti???p theo
    }

    wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode ECB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode ECB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_CBC_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[8]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // tr?????ng h???p input t??? screen
    {
        /* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input t??? screen
	{
		/* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
		string sIV(wIV.begin(), wIV.end()); //n???u convert string kh??ng c?? ti???ng vi???t d??ng c??ch n??y c??ng ???????c

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
    string plain = wstring_to_string(input); // convert wtring ti???ng vi???t sang string d???ng utf8
    string cipher, encoded, recovered;       //khai b??o ?????u v??o

    // Pretty print key
    encoded.clear();                     // x??a gi?? tr??? hi???n t???i c???a encoded
    StringSource(key, sizeof(key), true, // chuy???n m???ng byte "key" sang chu???i "encoded" d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xu???t wencoded b???ng wcout v?? 2 d??ng khai b??o ??? h??m main

    // Pretty print iv
	encoded.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(iv, sizeof(iv), true, //chuy???n m???ng byte "iv" sang chu???i "encoded" d?????i d???ng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xu???t wencoded2 b???ng wcout v?? 2 d??ng khai b??o ??? h??m main
    CBC_Mode<DES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode CBC
    try                          // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        wcout << L"plain text: " << input << endl; // xu???t plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e g???i h??m t???o key v???i 2 m???ng key v?? iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuy???n ?????i chu???i plain qua lu???ng "e" th??nh chu???i cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //n???u c?? l???i, th??ng b??o v?? tho??t ch????ng tr??nh
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xo?? gi?? tr??? hi???n t???i c???a encode
    StringSource(cipher, true, // chuy???n chu???i cipher th??nh chu???i encoded d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuy???n string encoded sang wstring wencoded3 ????? xu???t b???ng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xu???t ciphertext 
    
    // ?????c key t??? DES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? DES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CBC_Mode<DES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode CBC
    try  // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// ?????i t?????ng d g???i h??m t???o key v???i 2 m???ng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuy???n chu???i cipher b???ng lu???ng "d" sang chu???i recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuy???n ?????i chu???i utf8 "recovered" ???????c decryption th??nh wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xu???t chu???i wstring recov
    }
    catch (const CryptoPP::Exception &e) // n???u ph???n code trong ??o???n try c?? l???i th???c hi???n ph???n code trong ??o???n catch
    {
        cerr << e.what() << endl; // b??o l???i v?? d???ng ch????ng tr??nh
        exit(1);
    }

    double encTime = 0; //t???ng th???i gian Encryption
    double decTime = 0; //t???ng th???i gian Decryption
    double total = 0;   //t???ng th???i gian Mode
    int round = 1;
    while(round < 10001) // th???c hi???n ??o th???i gian encryption 10000 l???n
    {
        //ENCRYPTION
        int enc_start = clock();  // th???i gian b???t ?????u th???c hi??n encryption
        int mode_start = clock(); // th???i gian b???t ?????u c???a mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // th???i gian k???t th??c encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // t???ng h???p th???i gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // th???i gian b???t ?????u th???c hi???n decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered)) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // th???i gian k???t th??c decryption
        int mode_end = clock();                                                   // th???i gian k???t th??c mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian mode
        round++;                                                                  // round ti???p theo
    }

    wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode CBC: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CBC: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_OFB_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[8]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // tr?????ng h???p input t??? screen
    {
        /* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input t??? screen
	{
		/* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
		string sIV(wIV.begin(), wIV.end()); //n???u convert string kh??ng c?? ti???ng vi???t d??ng c??ch n??y c??ng ???????c

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
    string plain = wstring_to_string(input); // convert wtring ti???ng vi???t sang string d???ng utf8
    string cipher, encoded, recovered;       //khai b??o ?????u v??o

    // Pretty print key
    encoded.clear();                     // x??a gi?? tr??? hi???n t???i c???a encoded
    StringSource(key, sizeof(key), true, // chuy???n m???ng byte "key" sang chu???i "encoded" d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xu???t wencoded b???ng wcout v?? 2 d??ng khai b??o ??? h??m main

    // Pretty print iv
	encoded.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(iv, sizeof(iv), true, //chuy???n m???ng byte "iv" sang chu???i "encoded" d?????i d???ng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xu???t wencoded2 b???ng wcout v?? 2 d??ng khai b??o ??? h??m main
    OFB_Mode<DES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode OFB
    try                          // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        wcout << L"plain text: " << input << endl; // xu???t plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e g???i h??m t???o key v???i 2 m???ng key v?? iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuy???n ?????i chu???i plain qua lu???ng "e" th??nh chu???i cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //n???u c?? l???i, th??ng b??o v?? tho??t ch????ng tr??nh
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xo?? gi?? tr??? hi???n t???i c???a encode
    StringSource(cipher, true, // chuy???n chu???i cipher th??nh chu???i encoded d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuy???n string encoded sang wstring wencoded3 ????? xu???t b???ng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xu???t ciphertext 
    
    // ?????c key t??? DES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? DES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    OFB_Mode<DES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode OFB
    try  // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// ?????i t?????ng d g???i h??m t???o key v???i 2 m???ng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuy???n chu???i cipher b???ng lu???ng "d" sang chu???i recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuy???n ?????i chu???i utf8 "recovered" ???????c decryption th??nh wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xu???t chu???i wstring recov
    }
    catch (const CryptoPP::Exception &e) // n???u ph???n code trong ??o???n try c?? l???i th???c hi???n ph???n code trong ??o???n catch
    {
        cerr << e.what() << endl; // b??o l???i v?? d???ng ch????ng tr??nh
        exit(1);
    }

    double encTime = 0; //t???ng th???i gian Encryption
    double decTime = 0; //t???ng th???i gian Decryption
    double total = 0;   //t???ng th???i gian Mode
    int round = 1;
    while(round < 10001) // th???c hi???n ??o th???i gian encryption 10000 l???n
    {
        //ENCRYPTION
        int enc_start = clock();  // th???i gian b???t ?????u th???c hi??n encryption
        int mode_start = clock(); // th???i gian b???t ?????u c???a mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // th???i gian k???t th??c encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // t???ng h???p th???i gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // th???i gian b???t ?????u th???c hi???n decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // th???i gian k???t th??c decryption
        int mode_end = clock();                                                   // th???i gian k???t th??c mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian mode
        round++;                                                                  // round ti???p theo
    }

    wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode OFB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode OFB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_CFB_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[8]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // tr?????ng h???p input t??? screen
    {
        /* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input t??? screen
	{
		/* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
		string sIV(wIV.begin(), wIV.end()); //n???u convert string kh??ng c?? ti???ng vi???t d??ng c??ch n??y c??ng ???????c

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
    string plain = wstring_to_string(input); // convert wtring ti???ng vi???t sang string d???ng utf8
    string cipher, encoded, recovered;       //khai b??o ?????u v??o

    // Pretty print key
    encoded.clear();                     // x??a gi?? tr??? hi???n t???i c???a encoded
    StringSource(key, sizeof(key), true, // chuy???n m???ng byte "key" sang chu???i "encoded" d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xu???t wencoded b???ng wcout v?? 2 d??ng khai b??o ??? h??m main

    // Pretty print iv
	encoded.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(iv, sizeof(iv), true, //chuy???n m???ng byte "iv" sang chu???i "encoded" d?????i d???ng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xu???t wencoded2 b???ng wcout v?? 2 d??ng khai b??o ??? h??m main
    CFB_Mode<DES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode CFB
    try                          // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        wcout << L"plain text: " << input << endl; // xu???t plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e g???i h??m t???o key v???i 2 m???ng key v?? iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuy???n ?????i chu???i plain qua lu???ng "e" th??nh chu???i cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //n???u c?? l???i, th??ng b??o v?? tho??t ch????ng tr??nh
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xo?? gi?? tr??? hi???n t???i c???a encode
    StringSource(cipher, true, // chuy???n chu???i cipher th??nh chu???i encoded d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuy???n string encoded sang wstring wencoded3 ????? xu???t b???ng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xu???t ciphertext 
    
    // ?????c key t??? DES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? DES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CFB_Mode<DES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode CFB
    try  // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// ?????i t?????ng d g???i h??m t???o key v???i 2 m???ng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuy???n chu???i cipher b???ng lu???ng "d" sang chu???i recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuy???n ?????i chu???i utf8 "recovered" ???????c decryption th??nh wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xu???t chu???i wstring recov
    }
    catch (const CryptoPP::Exception &e) // n???u ph???n code trong ??o???n try c?? l???i th???c hi???n ph???n code trong ??o???n catch
    {
        cerr << e.what() << endl; // b??o l???i v?? d???ng ch????ng tr??nh
        exit(1);
    }

    double encTime = 0; //t???ng th???i gian Encryption
    double decTime = 0; //t???ng th???i gian Decryption
    double total = 0;   //t???ng th???i gian Mode
    int round = 1;
    while(round < 10001) // th???c hi???n ??o th???i gian encryption 10000 l???n
    {
        //ENCRYPTION
        int enc_start = clock();  // th???i gian b???t ?????u th???c hi??n encryption
        int mode_start = clock(); // th???i gian b???t ?????u c???a mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // th???i gian k???t th??c encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // t???ng h???p th???i gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // th???i gian b???t ?????u th???c hi???n decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // th???i gian k???t th??c decryption
        int mode_end = clock();                                                   // th???i gian k???t th??c mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian mode
        round++;                                                                  // round ti???p theo
    }

    wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode CFB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CFB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void DES_CTR_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[DES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[8]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("DES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from DES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(16); // Pump first 16 bytes
    }
    else // tr?????ng h???p input t??? screen
    {
        /* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
        string SKey(WKey.begin(), WKey.end());

        /* Reading key from  input screen*/
        StringSource ss(SKey, false);

        /* Create byte array space for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));

        /*Copy data to key*/
        ss.Detach(new Redirector(copykey));
        ss.Pump(16); // Pump first 16 bytes
    }

    if (WKey != L"File") //DES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file DES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("DES_key.key"));
    }
    // IV generation
    byte iv[DES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[8]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("DES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from DES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // IV input t??? screen
	{
		/* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
		string sIV(wIV.begin(), wIV.end()); //n???u convert string kh??ng c?? ti???ng vi???t d??ng c??ch n??y c??ng ???????c

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
    string plain = wstring_to_string(input); // convert wtring ti???ng vi???t sang string d???ng utf8
    string cipher, encoded, recovered;       //khai b??o ?????u v??o

    // Pretty print key
    encoded.clear();                     // x??a gi?? tr??? hi???n t???i c???a encoded
    StringSource(key, sizeof(key), true, // chuy???n m???ng byte "key" sang chu???i "encoded" d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xu???t wencoded b???ng wcout v?? 2 d??ng khai b??o ??? h??m main

    // Pretty print iv
	encoded.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(iv, sizeof(iv), true, //chuy???n m???ng byte "iv" sang chu???i "encoded" d?????i d???ng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xu???t wencoded2 b???ng wcout v?? 2 d??ng khai b??o ??? h??m main
    CTR_Mode<DES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode CTR
    try                          // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        wcout << L"plain text: " << input << endl; // xu???t plaintext
        e.SetKeyWithIV(key, sizeof(key), iv); //e g???i h??m t???o key v???i 2 m???ng key v?? iv

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,             //chuy???n ?????i chu???i plain qua lu???ng "e" th??nh chu???i cipher
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource
    }
    catch (const CryptoPP::Exception &e) //n???u c?? l???i, th??ng b??o v?? tho??t ch????ng tr??nh
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();           // xo?? gi?? tr??? hi???n t???i c???a encode
    StringSource(cipher, true, // chuy???n chu???i cipher th??nh chu???i encoded d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring wencoded3(encoded.begin(), encoded.end()); // chuy???n string encoded sang wstring wencoded3 ????? xu???t b???ng wcout
    wcout << L"cipher text: " << wencoded3 << endl;    // xu???t ciphertext 
    
    // ?????c key t??? DES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("DES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from DES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? DES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("DES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from DES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CTR_Mode<DES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode CTR
    try  // th???c hi???n kh???i l???ch d?????i, n???u kh??ng ???????c b??o l???i trong ph???n catch
    {
        d.SetKeyWithIV(key, sizeof(key), iv);// ?????i t?????ng d g???i h??m t???o key v???i 2 m???ng key, iv

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true, // chuy???n chu???i cipher b???ng lu???ng "d" sang chu???i recovered
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring recov = string_to_wstring(recovered);  // chuy???n ?????i chu???i utf8 "recovered" ???????c decryption th??nh wstring "recov"
        wcout << L"recovered text: " << recov << endl; // xu???t chu???i wstring recov
    }
    catch (const CryptoPP::Exception &e) // n???u ph???n code trong ??o???n try c?? l???i th???c hi???n ph???n code trong ??o???n catch
    {
        cerr << e.what() << endl; // b??o l???i v?? d???ng ch????ng tr??nh
        exit(1);
    }

    double encTime = 0; //t???ng th???i gian Encryption
    double decTime = 0; //t???ng th???i gian Decryption
    double total = 0;   //t???ng th???i gian Mode
    int round = 1;
    while(round < 10001) // th???c hi???n ??o th???i gian mode ch???y 10000 l???n
    {
        //ENCRYPTION
        int enc_start = clock();  // th???i gian b???t ?????u th???c hi??n encryption
        int mode_start = clock(); // th???i gian b???t ?????u c???a mode
        e.SetKeyWithIV(key, sizeof(key),iv);
        cipher.clear();
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher),
                                                      StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                    // StringSource

        int enc_end = clock();                                            // th???i gian k???t th??c encryption
        encTime += (enc_end - enc_start) / double(CLOCKS_PER_SEC) * 1000; // t???ng h???p th???i gian encryption
        
        //DECRYPTION
        int dec_start = clock(); // th???i gian b???t ?????u th???c hi???n decryption
        d.SetKeyWithIV(key, sizeof(key),iv);
        // The StreamTransformationFilter removes
        //  padding as required.
        recovered.clear();
        StringSource s2(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                        // StringSource
        int dec_end = clock();                                                    // th???i gian k???t th??c decryption
        int mode_end = clock();                                                   // th???i gian k???t th??c mode
        decTime += (dec_end - dec_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian decryption
        total += (mode_end - mode_start) / double(CLOCKS_PER_SEC) * 1000;         // t???ng h???p th???i gian mode
        round++;                                                                  // round ti???p theo
    }

    wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode CTR: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CTR: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}

