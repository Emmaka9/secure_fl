// masking.h
//
// Header file for the masking engine. It declares all the functions
// for ECDH key exchange and ChaCha20-based mask generation.

#ifndef MASKING_H
#define MASKING_H

#include "common.h"

// Generates a new ECDH key pair using OpenSSL.
SafePKey GenerateECDHKeys();

// Serializes an ECDH public key into a byte vector for transmission.
ECDHPublicKey SerializePublicKey(const SafePKey& keys);

// Deserializes a byte vector back into an OpenSSL public key object.
SafePKey DeserializePublicKey(const ECDHPublicKey& pubKeyBytes);

// Computes a shared secret between my private key and a peer's public key.
std::vector<unsigned char> ComputeSharedSecret(const SafePKey& myKeys, const SafePKey& peerPubKey);

// Generates the final additive mask for a client.
DCRTPoly GenerateMask(uint32_t myId, const SafePKey& myKeys, 
                      const std::map<uint32_t, ECDHPublicKey>& allPublicKeys,
                      CryptoContext<DCRTPoly>& cc);

#endif // MASKING_H
