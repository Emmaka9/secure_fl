// common.h
//
// This header file defines all the shared data structures and common includes
// for the entire project. It acts as a central "dictionary" that all other
// modules use to communicate and understand each other's data types.

#ifndef COMMON_H
#define COMMON_H

#include "pke/openfhe.h"
#include <vector>
#include <iostream>
#include <iomanip>
#include <cmath>
#include <random>
#include <memory> // For std::unique_ptr
#include <map>    // For std::map

// Forward declare OpenSSL's EVP_PKEY type to avoid including heavy OpenSSL headers here.
// This is a common practice to speed up compilation.
struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;

// Use the lbcrypto namespace for all OpenFHE types
using namespace lbcrypto;

// --- Custom Data Structures for the MK-CKKS Protocol ---

class MKeyGenSecretKey {
public:
    DCRTPoly s;
};

class MKeyGenPublicKey {
public:
    DCRTPoly b;
    DCRTPoly a; // Common reference polynomial
};

class MKeyGenKeyPair {
public:
    MKeyGenPublicKey pk;
    MKeyGenSecretKey sk;
};

class MKCiphertext {
public:
    DCRTPoly c0;
    DCRTPoly c1;
};

// Represents the data a client sends to the server for aggregation.
// It now contains the MASKED partial decryption.
class ClientShare {
public:
    DCRTPoly c0;
    DCRTPoly d_masked; // This now holds the masked value: d_i + r_i
};

// --- Custom Data Structures for the Masking Protocol ---

// A custom deleter for the OpenSSL EVP_PKEY object to be used with smart pointers.
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* pkey) const;
};

// Define a safe, modern C++ way to handle the OpenSSL key object.
using SafePKey = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

// A convenient type alias for a serialized public key.
using ECDHPublicKey = std::vector<unsigned char>;

#endif // COMMON_H
