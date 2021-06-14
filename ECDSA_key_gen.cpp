#include <assert.h>

#include <iostream>
using std::wcout;
using std::wcin;
using std::cerr;
using std::endl;

#include <string>
using std::string;

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

#include "cryptopp/oids.h"
using CryptoPP::OID;

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA512>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA512>::PrivateKey& privateKey, ECDSA<ECP, SHA512>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA512>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA512>::PublicKey& key );

int main()
{
     // Scratch result
    bool result = false;  
    
    // Private and Public keys
    ECDSA<ECP, SHA512>::PrivateKey privateKey;
    ECDSA<ECP, SHA512>::PublicKey publicKey;
    
    /////////////////////////////////////////////
    // Generate Keys
    result = GeneratePrivateKey( CryptoPP::ASN1::secp256r1(), privateKey );
    assert( true == result );
    if( !result ) { return -1; }

    result = GeneratePublicKey( privateKey, publicKey );
    assert( true == result );
    if( !result ) { return -2; }
    
    /////////////////////////////////////////////
    // Save key in PKCS#9 and X.509 format    
    SavePrivateKey( "ec.private.key", privateKey );
    SavePublicKey( "ec.public.key", publicKey );
    
}

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA512>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
     
    return key.Validate( prng, 3 );
}

bool GeneratePublicKey( const ECDSA<ECP, SHA512>::PrivateKey& privateKey, ECDSA<ECP, SHA512>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA512>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA512>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}