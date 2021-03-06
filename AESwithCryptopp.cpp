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
using CryptoPP::AAD_CHANNEL;
using CryptoPP::DEFAULT_CHANNEL;
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

#include "cryptopp/aes.h"
using CryptoPP::AES;

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
void AES_ECB_MODE(wstring, wstring);
void AES_CBC_MODE(wstring, wstring, wstring);
void AES_OFB_MODE(wstring, wstring, wstring);
void AES_CFB_MODE(wstring, wstring, wstring);
void AES_CTR_MODE(wstring, wstring, wstring);
void AES_XTS_MODE(wstring, wstring, wstring);
void AES_CCM_MODE(wstring, wstring, wstring, wstring);
void AES_GCM_MODE(wstring, wstring, wstring, wstring);

int main(int argc, char *argv[])
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);

    wstring enter; // tr??nh l???i getline
    int mode; // Ch???n mode ????? th???c hi???n AES
    wcout << L"Choose a mode of operation:\n";
    wcout << L"\t0. ECB Mode\n";
    wcout << L"\t1. CBC Mode\n";
    wcout << L"\t2. OFB Mode\n";
    wcout << L"\t3. CFB Mode\n";
    wcout << L"\t4. CTR Mode\n";
    wcout << L"\t5. XTS Mode\n";
    wcout << L"\t6. CCM Mode\n";
    wcout << L"\t7. GCM Mode\n";
    wcout << L"====================\n";
    wcout << L"Mode: ";
    wcin >> mode;
    getline(wcin, enter);

    wcout << L"Enter plaintext:  ";
    wstring plain; // plaintext c?? h??? tr??? ti???ng vi???t
    wcin.ignore();
    getline(wcin, plain);
    wstring authenMess; // Authentication Message d??ng cho CCM v?? GCM mode
    if(mode == 6 || mode == 7)
    {
        wcout << L"Enter Authentication Message: ";
        wcin.ignore();
        getline(wcin, authenMess);
    }
    wstring key;
    int type_key; // Ch???n c??ch input key
    wcout << L"Choose type of key input:\n";
    wcout << L"\t1. Random key\n";
    wcout << L"\t2. From file \n";
    wcout << L"\t3. From screen\n";
    wcout << L"Type of key input: ";
    wcin >> type_key;
    getline(wcin, enter);
    switch (type_key)
    {
    case 1:
        key = L"Random"; //  Random key 
        break;
    case 2:
        key = L"File";  // L???y key t??? file
        break;
    case 3: // Nh???p t??? m??n h??nh terminal
        if(mode == 6 || mode == 7) // N???u l?? mode CCM ho???c GCM
            wcout << L"Enter key (32 bytes): ";
        else
            wcout << L"Enter key (16 bytes): ";
        wcin.ignore();
        getline(wcin, key);
        break;
    default:
        key = L"Random";
        break;
    }

    wstring iv;
    if (mode != 0) // Kh??c ECB mode m???i s??? d???ng iv
    {
        int type_iv; // Ch???n c??ch input iv
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
            if(mode == 6 || mode == 7) // Mode CCM ho???c GCM
                wcout << L"Enter iv (12 bytes): ";
            else
                wcout << L"Enter iv (16 bytes): ";
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
        wcout << L"====AES ECB MODE====" << endl;
        AES_ECB_MODE(plain, key);
        break;

    case 1:
        wcout << L"====AES CBC MODE===="<<endl;
		AES_CBC_MODE(plain, key, iv);
		break;
	
	case 2:
        wcout << L"====AES OFB MODE===="<<endl;
		AES_OFB_MODE(plain, key, iv);
		break;

	case 3:
        wcout << L"====AES CFB MODE===="<<endl;
		AES_CFB_MODE(plain, key, iv);
		break;

	case 4:
		wcout<<L"====AES CTR MODE===="<<endl;
        AES_CTR_MODE(plain, key, iv);
		break;

	case 5:
		wcout<<L"====AES XTS MODE===="<<endl;
        AES_XTS_MODE(plain, key, iv);
		break;

    case 6:
		wcout<<L"====AES CCM MODE===="<<endl;
        AES_CCM_MODE(plain, key, iv, authenMess);
		break;

	case 7:
        wcout<<L"====AES GCM MODE===="<<endl;
        AES_GCM_MODE(plain, key, iv, authenMess);
		break;

    default:
        wcout << L"====AES ECB MODE====" << endl;
        AES_ECB_MODE(plain, iv);
        break;
    }
    return 0;
}

void AES_ECB_MODE(wstring input, wstring WKey)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    byte key[AES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[16]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("AES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from AES_key.key  to  key */
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

    if (WKey != L"File") //AES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file AES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("AES_key.key"));
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

    ECB_Mode<AES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode ECB
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
    wcout << L"cipher text: " << wencoded3 << endl;    // xu???t ciphertext
    // ?????c key t??? AES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("AES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from AES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes

    ECB_Mode<AES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode ECB
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
void AES_CBC_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[AES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[16]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("AES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from AES_key.key  to  key */
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

    if (WKey != L"File") //AES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file AES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("AES_key.key"));
    }
    // IV generation
    byte iv[AES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[16]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("AES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from AES_key.key  to  key */ 
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
		//Write key to file AES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "AES_iv.key"));
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
    CBC_Mode<AES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode CBC
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
    
    // ?????c key t??? AES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("AES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from AES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? AES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("AES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from AES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CBC_Mode<AES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode CBC
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
void AES_OFB_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[AES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[16]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("AES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from AES_key.key  to  key */
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

    if (WKey != L"File") //AES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file AES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("AES_key.key"));
    }
    // IV generation
    byte iv[AES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[16]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("AES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from AES_key.key  to  key */ 
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
		//Write key to file AES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "AES_iv.key"));
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
    OFB_Mode<AES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode OFB
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
    
    // ?????c key t??? AES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("AES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from AES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? AES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("AES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from AES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    OFB_Mode<AES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode OFB
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
    wcout << L"Total time for 10000 rounds:\n\tMode OFB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode OFB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void AES_CFB_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[AES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[16]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("AES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from AES_key.key  to  key */
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

    if (WKey != L"File") //AES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file AES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("AES_key.key"));
    }
    // IV generation
    byte iv[AES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[16]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("AES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from AES_key.key  to  key */ 
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
		//Write key to file AES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "AES_iv.key"));
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
    CFB_Mode<AES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode CFB
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
    
    // ?????c key t??? AES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("AES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from AES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? AES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("AES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from AES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CFB_Mode<AES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode CFB
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
    wcout << L"Total time for 10000 rounds:\n\tMode CFB: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CFB: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void AES_CTR_MODE(wstring input, wstring WKey, wstring wIV)
{
    AutoSeededRandomPool prng;        // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv
    // Key generation
    byte key[AES::DEFAULT_KEYLENGTH]; // kh???i t???o m???ng byte key[16]

    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("AES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from AES_key.key  to  key */
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

    if (WKey != L"File") //AES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file AES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("AES_key.key"));
    }
    // IV generation
    byte iv[AES::BLOCKSIZE]; //kh???i t???o m???ng byte iv[16]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("AES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from AES_key.key  to  key */ 
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
		//Write key to file AES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "AES_iv.key"));
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
    CTR_Mode<AES>::Encryption e; //khai b??o ?????i t?????ng encryption e v???i mode CTR
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
    
    // ?????c key t??? AES_key.key d??ng cho Decryption
    /* Reading key from file*/
    FileSource fs("AES_key.key", false);
    /*Create space  for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data from AES_key.key  to  key */
    fs.Detach(new Redirector(copykey));
    fs.Pump(16); // Pump first 16 bytes
    // ?????c iv t??? AES_iv.key d??ng cho Decryption
    /* Reading iv from file*/
	FileSource fs2("AES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	/*Copy data from AES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes

    CTR_Mode<AES>::Decryption d; // kh???i t???o ?????i t?????ng decryption "d" v???i mode CTR
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
    wcout << L"Total time for 10000 rounds:\n\tMode CTR: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CTR: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void AES_XTS_MODE(wstring input, wstring WKey, wstring wIV)
{
	AutoSeededRandomPool prng; // khai b??o ?????i t?????ng prng ????? s??? d???ng cho random block key, iv

	SecByteBlock key(2*AES::DEFAULT_KEYLENGTH); // kh???i t???o m???ng byte key[32]
	if(WKey == L"Random") // key input b???ng random
	{
		prng.GenerateBlock(key, key.size()); // random key b???ng GenerateBlock
	}
	else if(WKey == L"File") // key input b???ng File
	{
		/* Reading key from file*/
		FileSource fs("AES_key.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copykey(key, key.size());
		/*Copy data from AES_key.key  to  key */ 
		fs.Detach(new Redirector(copykey));
		fs.Pump(32);  // Pump first 32 bytes
	}
	else // Key input t??? screen
	{
		/* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
		string SKey(WKey.begin(), WKey.end()); 

		/* Reading key from  input screen*/
		StringSource ss(SKey, false);

		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(key, key.size());

		/*Copy data to key*/ 
		ss.Detach(new Redirector(copykey));
		ss.Pump(32);  // Pump first 32 bytes
	}
	if(WKey != L"File")
	{
		//Write key to file AES_key.key 
		StringSource ss(key, key.size(), true , new FileSink( "AES_key.key"));
	}

	SecByteBlock iv(AES::BLOCKSIZE); //kh???i t???o m???ng byte iv[16]
	if(wIV == L"Random") // iv input b???ng random
	{
		prng.GenerateBlock(iv, iv.size()); // random iv b???ng GenerateBlock
	}
	else if(wIV == L"File") //iv input b???ng File
	{
		/* Reading key from file*/
		FileSource fs("AES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, iv.size());
		/*Copy data from AES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(16);  // Pump first 16 bytes
	}
	else // iv input t??? screen
	{
		/* convert WKey(wstring) sang SKey(string) ????? x??? l?? */
		string sIV(wIV.begin(), wIV.end()); 

		/* Reading key from  input screen*/
		StringSource sss(sIV, false);

		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(iv, iv.size());

		/*Copy data to key*/ 
		sss.Detach(new Redirector(copykey));
		sss.Pump(16);  // Pump first 16 bytes
	}

	if(wIV != L"File")
	{
		//Write key to file AES_key.key 
		StringSource sss(iv, iv.size(), true , new FileSink( "AES_iv.key"));
	}

	string plain = wstring_to_string(input); // convert wtring ti???ng vi???t sang string d???ng utf8
	string cipher, encoded, recovered; //khai b??o ?????u v??o

	// Pretty print key
	encoded.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	wstring wencoded1(encoded.begin(), encoded.end()); // convert string encoded sang wstring wencoded
	wcout << L"key: " << wencoded1 << endl; //xu???t key d???ng hex

	// Pretty print iv
	encoded.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(iv, iv.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded.begin(), encoded.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xu???t iv d???ng hex

	XTS< AES >::Encryption e;  // kh???i t???o ?????i t?????ng encryption e v???i mode XTS
	try
	{
		wcout << "plain text: " << input << endl;
		e.SetKeyWithIV( key, key.size(), iv );

		// The StreamTransformationFilter adds padding
		//  as requiredec. ECB and XTS Mode must be padded
		//  to the block size of the cipher.
		StringSource ss( plain, true, 
			new StreamTransformationFilter( e,
				new StringSink( cipher ),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	
	// Pretty print
	encoded.clear();// xo?? gi?? tr??? hi???n t???i c???a encode
	StringSource(cipher, true, // chuy???n chu???i cipher th??nh chu???i encoded d?????i d???ng hex
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSourceen

	wstring wencoded3(encoded.begin(), encoded.end()); // chuy???n string encoded sang wstring wencoded3 ???? xu???t b???ng wcout
	wcout << L"cipher text: " << wencoded3 << endl; // xu???t ciphertext

	/* Reading key from file*/
	FileSource fs("AES_key.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copykey(key, key.size());
	/*Copy data from AES_key.key  to  key */ 
	fs.Detach(new Redirector(copykey));
	fs.Pump(16);  // Pump first 16 bytes

	/* Reading iv from file*/
	FileSource fs2("AES_iv.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copyiv(iv, iv.size());
	/*Copy data from AES_key.key  to  key */ 
	fs2.Detach(new Redirector(copyiv));
	fs2.Pump(16);  // Pump first 16 bytes
	
	XTS< AES >::Decryption d;  // kh???i t???o ?????i t?????ng decryption d v???i mode XTS
	try
	{
		d.SetKeyWithIV( key, key.size(), iv );

		// The StreamTransformationFilter removes
		//  padding as requiredec.
		StringSource ss( cipher, true, 
			new StreamTransformationFilter( d,
				new StringSink( recovered ),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter
		); // StringSource

		wstring recov = string_to_wstring(recovered);// chuy???n ?????i chu???i utf8 "recovered" ???????c decryption th??nh wstring "recov"
		wcout<< L"recovered text: "<< recov<<endl;// xu???t chu???i wstring recov
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	double encTime = 0; //t???ng th???i gian Encryption
	double decTime = 0;	//t???ng th???i gian Decryption
	double total = 0; //t???ng th???i gian Mode
    int round = 1;
	while(round < 10001) // th???c hi???n ??o th???i gian mode ch???y 10000 l???n
	{
        //ENCRYPTION
		int enc_start = clock(); // th???i gian b???t ?????u th???c hi??n encryption
		int mode_start = clock(); // th???i gian b???t ?????u c???a mode
		e.SetKeyWithIV(key, key.size(), iv); 
		cipher.clear();
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss( plain, true, 
			new StreamTransformationFilter( e,
				new StringSink( cipher ),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter      
		); // StringSource
		int enc_end = clock(); // th???i gian k???t th??c encryption
		encTime += (enc_end - enc_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian encryption
        
        //DECRYPTION
		int dec_start = clock(); // th???i gian b???t ?????u th???c hi???n decryption
		d.SetKeyWithIV(key, key.size(), iv);
		// The StreamTransformationFilter removes
		//  padding as required.
		recovered.clear();
		StringSource sss( cipher, true, 
			new StreamTransformationFilter( d,
				new StringSink( recovered ),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter
		); // StringSource
		int dec_end = clock(); // th???i gian k???t th??c decryption
		int mode_end = clock(); // th???i gian k???t th??c mode
		decTime += (dec_end - dec_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian decryption
		total += (mode_end - mode_start)/double(CLOCKS_PER_SEC)*1000; //t???ng h???p th???i gian mode
        round++; // round ti???p theo
	}
	
	wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode XTS: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode XTS: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void AES_CCM_MODE(wstring input, wstring WKey, wstring wIV, wstring authenMess)
{
    AutoSeededRandomPool prng;
    byte key[32];   // Khai b??o m???ng byte key[32]
    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("AES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from AES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(32); // Pump first 32 bytes
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
        ss.Pump(32); // Pump first 32 bytes
    }

    if (WKey != L"File") //AES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file AES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("AES_key.key"));
    }
    // IV generation
    byte iv[12]; //kh???i t???o m???ng byte iv[12]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("AES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from AES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(12);  // Pump first 12 bytes
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
		sss.Pump(12);  // Pump first 12 bytes
	}

	if(wIV != L"File") 
	{
		//Write key to file AES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "AES_iv.key"));
	}
    string encoded1;    

    // Pretty print key
    encoded1.clear();                     // x??a gi?? tr??? hi???n t???i c???a encoded
    StringSource(key, sizeof(key), true, // chuy???n m???ng byte "key" sang chu???i "encoded" d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded1)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded1.begin(), encoded1.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xu???t wencoded b???ng wcout v?? 2 d??ng khai b??o ??? h??m main

    // Pretty print iv
	encoded1.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(iv, sizeof(iv), true, //chuy???n m???ng byte "iv" sang chu???i "encoded" d?????i d???ng hex
		new HexEncoder(
			new StringSink(encoded1)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded1.begin(), encoded1.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xu???t wencoded2 b???ng wcout v?? 2 d??ng khai b??o ??? h??m main
   
    string adata = wstring_to_string(authenMess); // Authentication data
    string pdata = wstring_to_string(input); // Private message

    const int TAG_SIZE = 8;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/
    CCM< AES >::Encryption e; // ?????i t?????ng e thu???c AES Encryption c???a mode CCM 
    try
    {
        e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        // Not required for GCM mode (but required for CCM mode)
        e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_SIZE
        ); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource( cipher, true,
            new HexEncoder( new StringSink( encoded ), true, 16, " ") );
        wstring wencoded = string_to_wstring(encoded); // ????a ciphertext v??? d???ng wstring ????? xu???t
    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    //  cipher[ 0 ] |= 0x0F;
    //  cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    CCM< AES >::Decryption d; // ?????i t?????ng d thu???c AES Decryption c???a mode CCM 
    try
    {
         // Not recovered - sent via clear channel
        radata = adata;     
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );
        d.SpecifyDataLengths( radata.size(), enc.size(), 0 );
        // Sanity checks
        assert( cipher.size() == enc.size() + mac.size() );
        assert( enc.size() == pdata.size() );
        assert( TAG_SIZE == mac.size() );

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        // The order of the following calls are important
        df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert( true == b );

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        rpdata = retrieved;
        assert( rpdata == pdata );
        wstring wradata = string_to_wstring(radata);
        wstring wrpdata = string_to_wstring(rpdata);
        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        
        wcout << "==============================\n";
        wcout << L"Decrypted and Verified data. Ready for use." << endl;
        wcout << endl;
        wcout << L"adata length: " << adata.size() << endl;
        wcout << L"pdata length: " << pdata.size() << endl;
        wcout << L"pdata: " << input << endl;
        wcout << L"adata: " << authenMess << endl;
        wcout << L"cipher text: " << wencoded << endl;
        wcout << endl;
        wcout << L"recover privacy data:" << wrpdata << endl;
        wcout << L"recovered authentication data:" << wradata << endl;
        wcout << L"recovered pdata length: " << radata.size() << endl;
        wcout << L"recovered pdata length: " << rpdata.size() << endl;
        wcout << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    // ??O PERFORMANCE
    double encTime = 0; // T???ng th???i gian Encryption 
    double decTime = 0; // T???ng th???i gian Decryption 
    double total = 0; // T???ng th???i gian mode
    int round = 1;  // bi???n ?????m s??? round
    while(round < 10001)
    {
        int mode_start = clock();
        //ENCRYPTION
        int enc_start = clock();
            e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
            // Not required for GCM mode (but required for CCM mode)
            e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );
            cipher.clear();
            AuthenticatedEncryptionFilter ef( e,
                new StringSink( cipher ), false, TAG_SIZE
            ); // AuthenticatedEncryptionFilter

            // AuthenticatedEncryptionFilter::ChannelPut
            //  defines two channels: "" (empty) and "AAD"
            //   channel "" is encrypted and authenticated
            //   channel "AAD" is authenticated
            ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
            ef.ChannelMessageEnd("AAD");

            // Authenticated data *must* be pushed before
            //  Confidential/Authenticated data. Otherwise
            //  we must catch the BadState exception
            ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
            ef.ChannelMessageEnd("");
            encoded.clear();
            // Pretty print
            StringSource( cipher, true,
                new HexEncoder( new StringSink( encoded ), true, 16, " " ) );
            wstring wencoded = string_to_wstring(encoded); // ????a ciphertext v??? d???ng wstring ????? xu???t
        int enc_end = clock();
        encTime += (enc_end - enc_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian encryption
    
        //DECRYPTION
        int dec_start = clock();
            // Not recovered - sent via clear channel
            radata = adata;
            d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
            // Break the cipher text out into it's
            //  components: Encrypted Data and MAC Value
            string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
            string mac = cipher.substr( cipher.length()-TAG_SIZE );
            d.SpecifyDataLengths( radata.size(), enc.size(), 0 );
            // Sanity checks
            assert( cipher.size() == enc.size() + mac.size() );
            assert( enc.size() == pdata.size() );
            assert( TAG_SIZE == mac.size() );     

            // Object will not throw an exception
            //  during decryption\verification _if_
            //  verification fails.
            //AuthenticatedDecryptionFilter df( d, NULL,
            // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

            AuthenticatedDecryptionFilter df( d, NULL,
                AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

            // The order of the following calls are important
            df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
            df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
            df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

            // If the object throws, it will most likely occur
            //  during ChannelMessageEnd()
            df.ChannelMessageEnd( "AAD" );
            df.ChannelMessageEnd( "" );

            // If the object does not throw, here's the only
            //  opportunity to check the data's integrity
            bool b = false;
            b = df.GetLastResult();
            assert( true == b );

            // Remove data from channel
            string retrieved;
            size_t n = (size_t)-1;

            // Plain text recovered from enc.data()
            df.SetRetrievalChannel( "" );
            n = (size_t)df.MaxRetrievable();
            retrieved.resize( n );

            if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
            rpdata = retrieved;
            assert( rpdata == pdata );
            wstring wradata = string_to_wstring(radata);
            wstring wrpdata = string_to_wstring(rpdata);
            // Hmmm... No way to get the calculated MAC
            //  mac out of the Decryptor/Verifier. At
            //  least it is purported to be good.
            //df.SetRetrievalChannel( "AAD" );
            //n = (size_t)df.MaxRetrievable();
            //retrieved.resize( n );

            //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
            //assert( retrieved == mac );
        int dec_end = clock();
        int mode_end = clock();
        decTime += (dec_end - dec_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian decryption
        total += (mode_end - mode_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian decryption
        round++;
    }
    wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode CCM: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode CCM: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}
void AES_GCM_MODE(wstring input, wstring WKey, wstring wIV, wstring authenMess)
{
    AutoSeededRandomPool prng;
    byte key[32];   // Khai b??o m???ng byte key[32]
    if (WKey == L"Random") //tr?????ng h???p input b???ng random
    {
        prng.GenerateBlock(key, sizeof(key)); // random key b???ng GenerateBlock
    }
    else if (WKey == L"File") // tr?????ng h???p input t??? File
    {
        /* Reading key from file*/
        FileSource fs("AES_key.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copykey(key, sizeof(key));
        /*Copy data from AES_key.key  to  key */
        fs.Detach(new Redirector(copykey));
        fs.Pump(32); // Pump first 32 bytes
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
        ss.Pump(32); // Pump first 32 bytes
    }

    if (WKey != L"File") //AES_key.key s??? l??u key ???????c nh???p t??? screen ho???c random
    {
        //Write key to file AES_key.key
        StringSource ss(key, sizeof(key), true, new FileSink("AES_key.key"));
    }
    // IV generation
    byte iv[12]; //kh???i t???o m???ng byte iv[12]
	if(wIV == L"Random") //IV random
		prng.GenerateBlock(iv, sizeof(iv)); // t???o block key random
	else if(wIV == L"File") // IV input t??? file 
	{
		/* Reading key from file*/
		FileSource fs("AES_iv.key", false);
		/*Create space  for key*/ 
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data from AES_key.key  to  key */ 
		fs.Detach(new Redirector(copyiv));
		fs.Pump(12);  // Pump first 12 bytes
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
		sss.Pump(12);  // Pump first 12 bytes
	}

	if(wIV != L"File") 
	{
		//Write key to file AES_key.key 
		StringSource sss(iv, sizeof(iv), true , new FileSink( "AES_iv.key"));
	}
    string encoded1;    

    // Pretty print key
    encoded1.clear();                     // x??a gi?? tr??? hi???n t???i c???a encoded
    StringSource(key, sizeof(key), true, // chuy???n m???ng byte "key" sang chu???i "encoded" d?????i d???ng hex
                 new HexEncoder(
                     new StringSink(encoded1)) // HexEncoder
    );                                        // StringSource

    wstring wencoded(encoded1.begin(), encoded1.end()); // convert string encoded sang wstring wencoded
    wcout << L"key: " << wencoded << endl;            //xu???t wencoded b???ng wcout v?? 2 d??ng khai b??o ??? h??m main

    // Pretty print iv
	encoded1.clear(); // x??a gi?? tr??? hi???n t???i c???a encoded
	StringSource(iv, sizeof(iv), true, //chuy???n m???ng byte "iv" sang chu???i "encoded" d?????i d???ng hex
		new HexEncoder(
			new StringSink(encoded1)
		) // HexEncoder
	); // StringSource
	wstring wencoded2(encoded1.begin(), encoded1.end()); //convert string encoded sang wstring wencoded2
	wcout << L"iv: " << wencoded2 << endl; //xu???t wencoded2 b???ng wcout v?? 2 d??ng khai b??o ??? h??m main
   
    string adata = wstring_to_string(authenMess); // Authentication data
    string pdata = wstring_to_string(input); // Private message

    const int TAG_SIZE = 16;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/
    GCM< AES >::Encryption e; // ?????i t?????ng e thu???c AES Encryption c???a mode GCM 
    try
    {
        e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_SIZE
        ); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource( cipher, true,
            new HexEncoder( new StringSink( encoded ), true, 16, " " ) );
        wstring wencoded = string_to_wstring(encoded); // ????a ciphertext v??? d???ng wstring ????? xu???t
    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    //  cipher[ 0 ] |= 0x0F;
    //  cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    GCM< AES >::Decryption d; // ?????i t?????ng d thu???c AES Decryption c???a mode GCM 
    try
    {
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );

        // Sanity checks
        assert( cipher.size() == enc.size() + mac.size() );
        assert( enc.size() == pdata.size() );
        assert( TAG_SIZE == mac.size() );

        // Not recovered - sent via clear channel
        radata = adata;     

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        // The order of the following calls are important
        df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert( true == b );

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        rpdata = retrieved;
        assert( rpdata == pdata );
        wstring wradata = string_to_wstring(radata);
        wstring wrpdata = string_to_wstring(rpdata);
        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        wcout << "==============================\n";
        wcout << L"Decrypted and Verified data. Ready for use." << endl;
        wcout << endl;
        wcout << L"adata length: " << adata.size() << endl;
        wcout << L"pdata length: " << pdata.size() << endl;
        wcout << L"pdata: " << input << endl;
        wcout << L"adata: " << authenMess << endl;
        wcout << L"cipher text: " << wencoded << endl;
        wcout << endl;
        wcout << L"recover privacy data:" << wrpdata << endl;
        wcout << L"recovered authentication data:" << wradata << endl;
        wcout << L"recovered pdata length: " << radata.size() << endl;
        wcout << L"recovered pdata length: " << rpdata.size() << endl;
        wcout << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    // ??O PERFORMANCE
    double encTime = 0;
    double decTime = 0;
    double total = 0;
    int round = 1;
    while(round < 10001)
    {
        int mode_start = clock();
        //ENCRYPTION
        int enc_start = clock();
            e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
            // Not required for GCM mode (but required for CCM mode)
            // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );
            cipher.clear();
            AuthenticatedEncryptionFilter ef( e,
                new StringSink( cipher ), false, TAG_SIZE
            ); // AuthenticatedEncryptionFilter

            // AuthenticatedEncryptionFilter::ChannelPut
            //  defines two channels: "" (empty) and "AAD"
            //   channel "" is encrypted and authenticated
            //   channel "AAD" is authenticated
            ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
            ef.ChannelMessageEnd("AAD");

            // Authenticated data *must* be pushed before
            //  Confidential/Authenticated data. Otherwise
            //  we must catch the BadState exception
            ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
            ef.ChannelMessageEnd("");
            encoded.clear();
            // Pretty print
            StringSource( cipher, true,
                new HexEncoder( new StringSink( encoded ), true, 16, " " ) );
            wstring wencoded = string_to_wstring(encoded); // ????a ciphertext v??? d???ng wstring ????? xu???t
        int enc_end = clock();
        encTime += (enc_end - enc_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian encryption
    
        //DECRYPTION
        int dec_start = clock();
        
            d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

            // Break the cipher text out into it's
            //  components: Encrypted Data and MAC Value
            string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
            string mac = cipher.substr( cipher.length()-TAG_SIZE );

            // Sanity checks
            assert( cipher.size() == enc.size() + mac.size() );
            assert( enc.size() == pdata.size() );
            assert( TAG_SIZE == mac.size() );

            // Not recovered - sent via clear channel
            radata = adata;     

            // Object will not throw an exception
            //  during decryption\verification _if_
            //  verification fails.
            //AuthenticatedDecryptionFilter df( d, NULL,
            // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

            AuthenticatedDecryptionFilter df( d, NULL,
                AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

            // The order of the following calls are important
            df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
            df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
            df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

            // If the object throws, it will most likely occur
            //  during ChannelMessageEnd()
            df.ChannelMessageEnd( "AAD" );
            df.ChannelMessageEnd( "" );

            // If the object does not throw, here's the only
            //  opportunity to check the data's integrity
            bool b = false;
            b = df.GetLastResult();
            assert( true == b );

            // Remove data from channel
            string retrieved;
            size_t n = (size_t)-1;

            // Plain text recovered from enc.data()
            df.SetRetrievalChannel( "" );
            n = (size_t)df.MaxRetrievable();
            retrieved.resize( n );

            if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
            rpdata = retrieved;
            assert( rpdata == pdata );
            wstring wradata = string_to_wstring(radata);
            wstring wrpdata = string_to_wstring(rpdata);
            // Hmmm... No way to get the calculated MAC
            //  mac out of the Decryptor/Verifier. At
            //  least it is purported to be good.
            //df.SetRetrievalChannel( "AAD" );
            //n = (size_t)df.MaxRetrievable();
            //retrieved.resize( n );

            //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
            //assert( retrieved == mac );
        int dec_end = clock();
        int mode_end = clock();
        decTime += (dec_end - dec_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian decryption
        total += (mode_end - mode_start)/double(CLOCKS_PER_SEC)*1000; // t???ng h???p th???i gian decryption
        round++;
    }
    wcout << L"=======================================================\n";
    // xu???t th???i gian th???c hi???n 10000 v??ng v?? 1 v??ng
    wcout << L"Total time for 10000 rounds:\n\tMode GCM: " << total << " ms\n\tEncryption Time: " << encTime << " ms\n\tDecryption Time: " << decTime << " ms" << endl;
    wcout << L"Average time for each round:\n\tMode GCM: " << total / 10000 << " ms\n\tEncryption Time: " << encTime / 10000 << " ms\n\tDecryption Time: " << decTime / 10000 << " ms" << endl;
}