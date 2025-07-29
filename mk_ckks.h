// mk_ckks.h
//
// Header file for the MK-CKKS cryptographic engine. It declares all the
// low-level functions for the custom multi-key CKKS protocol.

#ifndef MK_CKKS_H
#define MK_CKKS_H

#include "common.h"

// --- Function Declarations for the Crypto Engine ---

DCRTPoly GenerateCRS(CryptoContext<DCRTPoly>& cc);

MKeyGenKeyPair KeyGenSingle(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a);

DCRTPoly encodeVector(CryptoContext<DCRTPoly>& cc, const std::vector<double>& vec);

MKCiphertext Encrypt(CryptoContext<DCRTPoly>& cc, const MKeyGenPublicKey& pk, const DCRTPoly& m);

// FIX: This function now correctly returns only the partial decryption polynomial.
DCRTPoly ComputePartialDecryption(CryptoContext<DCRTPoly>& cc, const MKeyGenSecretKey& sk, const MKCiphertext& ct);

std::vector<double> Decode(const DCRTPoly& finalPoly, CryptoContext<DCRTPoly>& cc, uint32_t dataSize);

#endif // MK_CKKS_H
