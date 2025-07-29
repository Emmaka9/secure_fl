// masking.cpp
//
// Implementation of the masking engine using OpenSSL for ECDH and ChaCha20.
// This engine is responsible for generating pairwise masks between clients
// such that the sum of all masks across the system is zero.

#include "masking.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <algorithm> // For std::min
#include <vector>

// --- Implementation of the EVP_PKEY_Deleter for smart pointers ---
// This enables SafePKey (std::unique_ptr) to automatically manage the memory
// of OpenSSL's EVP_PKEY objects, preventing memory leaks.
void EVP_PKEY_Deleter::operator()(EVP_PKEY* pkey) const {
    EVP_PKEY_free(pkey);
}

/**
 * @brief Generates a fresh ECDH key pair using the secp384r1 curve.
 * @return A SafePKey (smart pointer) containing the newly generated key pair.
 */
SafePKey GenerateECDHKeys() {
    // Create a parameter generation context for EC keys.
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX");

    // Initialize the key generation process.
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to initialize keygen");
    }

    // Set the elliptic curve to use. secp384r1 is a standard, secure curve.
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set EC curve");
    }

    // Generate the key pair.
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to generate key pair");
    }

    EVP_PKEY_CTX_free(pctx);
    // Wrap the raw pointer in a smart pointer for automatic memory management.
    return SafePKey(pkey);
}

/**
 * @brief Serializes an OpenSSL public key into a byte vector for network transmission.
 * @param keys A SafePKey containing the key pair.
 * @return A byte vector (ECDHPublicKey) holding the serialized public key.
 */
ECDHPublicKey SerializePublicKey(const SafePKey& keys) {
    unsigned char* buf = NULL;
    // i2d_PUBKEY converts the public key into a standard binary format (DER).
    size_t len = i2d_PUBKEY(keys.get(), &buf);
    if (len <= 0) {
        throw std::runtime_error("Failed to serialize public key");
    }
    ECDHPublicKey pubKeyBytes(buf, buf + len);
    OPENSSL_free(buf); // The buffer allocated by i2d_PUBKEY must be freed.
    return pubKeyBytes;
}

/**
 * @brief Deserializes a byte vector back into a usable OpenSSL public key object.
 * @param pubKeyBytes The byte vector containing the serialized key.
 * @return A SafePKey holding the deserialized public key.
 */
SafePKey DeserializePublicKey(const ECDHPublicKey& pubKeyBytes) {
    const unsigned char* p = pubKeyBytes.data();
    // d2i_PUBKEY parses the binary format back into an EVP_PKEY structure.
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, pubKeyBytes.size());
    if (!pkey) {
        throw std::runtime_error("Failed to deserialize public key");
    }
    return SafePKey(pkey);
}

/**
 * @brief Computes a shared secret using my private key and a peer's public key (ECDH).
 * @param myKeys My key pair (containing my private key).
 * @param peerPubKey The public key of the other party.
 * @return A byte vector containing the derived shared secret.
 */
std::vector<unsigned char> ComputeSharedSecret(const SafePKey& myKeys, const SafePKey& peerPubKey) {
    // Create a context for key derivation.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(myKeys.get(), NULL);
    if (!ctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX for derivation");

    // Initialize the derivation process.
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize derivation");
    }

    // Provide the peer's public key to perform the ECDH calculation.
    if (EVP_PKEY_derive_set_peer(ctx, peerPubKey.get()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set peer public key");
    }

    // Determine the required length of the shared secret.
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to determine secret length");
    }

    // Derive the secret and store it in the vector.
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to derive secret");
    }

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

/**
 * @brief Uses a seed to generate a pseudo-random DCRTPoly for masking.
 *
 * This function takes a seed (derived from an ECDH shared secret) and uses it
 * as a key for the ChaCha20 stream cipher. The cipher's output is a long stream
 * of pseudo-random bytes, which are then interpreted as coefficients to form a
 * polynomial. Crucially, each generated coefficient is reduced modulo the
 * correct prime for its ring dimension to ensure it is a valid member.
 *
 * @param seed The input seed (byte vector).
 * @param cc The crypto context, needed for polynomial parameters.
 * @return A pseudo-random polynomial in DCRTPoly format.
 */
DCRTPoly PRGToDCRTPoly(const std::vector<unsigned char>& seed, CryptoContext<DCRTPoly>& cc) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    
    // Use ChaCha20 to expand the seed into a long stream of random bytes.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_chacha20();
    unsigned char key[32] = {0}; // ChaCha20 uses a 256-bit key.
    unsigned char iv[16] = {0};  // and a 128-bit IV/nonce.

    // Use the beginning of the shared secret as the key.
    size_t len_to_copy = std::min(seed.size(), sizeof(key));
    std::copy(seed.begin(), seed.begin() + len_to_copy, key);

    // Calculate the total number of bytes needed to fill the entire DCRTPoly.
    size_t bytes_per_tower = params->GetRingDimension() * sizeof(uint64_t);
    size_t total_bytes = params->GetParams().size() * bytes_per_tower;
    std::vector<unsigned char> random_bytes(total_bytes);

    // "Encrypt" a zero buffer to get a pseudo-random stream from ChaCha20.
    int out_len;
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, random_bytes.data(), &out_len, random_bytes.data(), random_bytes.size());
    EVP_CIPHER_CTX_free(ctx);

    // Create a DCRTPoly and fill it from the generated random bytes.
    DCRTPoly random_poly(params, Format::EVALUATION, true);
    uint64_t* random_uints = reinterpret_cast<uint64_t*>(random_bytes.data());
    size_t uints_offset = 0;

    // Iterate through each tower (each prime modulus in the RNS representation).
    for (size_t i = 0; i < params->GetParams().size(); ++i) {
        // Get the parameters for the current RNS tower.
        auto tower_params = params->GetParams()[i];
        
        // Create the vector that will hold the coefficients for this tower.
        NativeVector tower_vec(params->GetRingDimension(), tower_params->GetModulus());
        const NativeInteger& modulus = tower_params->GetModulus();
        
        // For each coefficient in the tower...
        for (size_t j = 0; j < params->GetRingDimension(); ++j) {
            // The random 64-bit integer must be reduced by the tower's modulus
            // to be a valid coefficient in that finite field.
            tower_vec[j] = NativeInteger(random_uints[uints_offset + j]) % modulus;
        }

        // *** FIX: Wrap the vector in a NativePoly object before setting it. ***
        // A DCRTPoly is composed of NativePoly elements, not raw NativeVectors.
        NativePoly tower_poly(tower_params);
        tower_poly.SetValues(std::move(tower_vec), Format::EVALUATION);

        // Set the correctly-typed object in the DCRTPoly.
        random_poly.SetElementAtIndex(i, std::move(tower_poly));

        uints_offset += params->GetRingDimension();
    }
    return random_poly;
}


/**
 * @brief Generates the final additive mask for a single client.
 *
 * This function iterates through all other clients (peers). For each peer, it
 * computes a shared secret and uses it to generate a random polynomial `p_ij`.
 * To ensure that the sum of all masks across all clients cancels to zero,
 * the polynomial is subtracted if `myId < peerId` and added if `myId > peerId`.
 * This creates a system where `mask_i = sum(p_ij for j > i) - sum(p_ji for j < i)`.
 * Since `p_ij` and `p_ji` are generated from the same shared secret, they are
 * identical, and this scheme guarantees `sum(all masks) = 0`.
 *
 * @param myId The ID of the current client.
 * @param myKeys The ECDH key pair of the current client.
 * @param allPublicKeys A map of all client IDs to their public ECDH keys.
 * @param cc The crypto context.
 * @return The final DCRTPoly mask for this client.
 */
DCRTPoly GenerateMask(uint32_t myId, const SafePKey& myKeys, 
                      const std::map<uint32_t, ECDHPublicKey>& allPublicKeys,
                      CryptoContext<DCRTPoly>& cc) {
    
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly final_mask(params, Format::EVALUATION, true); // Initialize mask to zero.

    for (const auto& pair : allPublicKeys) {
        uint32_t peerId = pair.first;
        if (myId == peerId) continue; // Skip self.

        // Establish shared secret with the peer.
        SafePKey peerPubKey = DeserializePublicKey(pair.second);
        std::vector<unsigned char> sharedSecret = ComputeSharedSecret(myKeys, peerPubKey);

        // Generate a random polynomial from this shared secret.
        DCRTPoly p_ij = PRGToDCRTPoly(sharedSecret, cc);
        
        // Add or subtract based on ID comparison to ensure global cancellation.
        if (myId < peerId) {
            final_mask -= p_ij;
        } else {
            final_mask += p_ij;
        }
    }
    return final_mask;
}