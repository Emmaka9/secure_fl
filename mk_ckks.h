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

// MODIFIED: The function signature now correctly accepts the secret key (sk)
// which is necessary to perform the integrated partial decryption step.
MKCiphertext Encrypt(CryptoContext<DCRTPoly>& cc, 
                    const MKeyGenPublicKey& pk, 
                    const MKeyGenSecretKey& sk, // Added secret key parameter
                    const DCRTPoly& m);

// This function is now obsolete and has been fully commented out.
// DCRTPoly ComputePartialDecryption(CryptoContext<DCRTPoly>& cc, const MKeyGenSecretKey& sk, const MKCiphertext& ct);

std::vector<double> Decode(const DCRTPoly& finalPoly, CryptoContext<DCRTPoly>& cc, uint32_t dataSize);

#endif // MK_CKKS_H
