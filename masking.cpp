// masking.cpp
//
// Implementation of the masking engine using OpenSSL for ECDH and ChaCha20.

#include "masking.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <stdexcept>

// --- Implementation of the EVP_PKEY_Deleter for smart pointers ---
void EVP_PKEY_Deleter::operator()(EVP_PKEY* pkey) const {
    EVP_PKEY_free(pkey);
}

/**
 * @brief Generates a fresh ECDH key pair using the secp384r1 curve.
 */
SafePKey GenerateECDHKeys() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX");

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to initialize keygen");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set EC curve");
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to generate key pair");
    }

    EVP_PKEY_CTX_free(pctx);
    return SafePKey(pkey);
}

/**
 * @brief Serializes a public key into a byte vector.
 */
ECDHPublicKey SerializePublicKey(const SafePKey& keys) {
    unsigned char* buf = NULL;
    size_t len = i2d_PUBKEY(keys.get(), &buf);
    if (len <= 0) {
        throw std::runtime_error("Failed to serialize public key");
    }
    ECDHPublicKey pubKeyBytes(buf, buf + len);
    OPENSSL_free(buf);
    return pubKeyBytes;
}

/**
 * @brief Deserializes a byte vector into a public key object.
 */
SafePKey DeserializePublicKey(const ECDHPublicKey& pubKeyBytes) {
    const unsigned char* p = pubKeyBytes.data();
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, pubKeyBytes.size());
    if (!pkey) {
        throw std::runtime_error("Failed to deserialize public key");
    }
    return SafePKey(pkey);
}

/**
 * @brief Computes the shared secret via ECDH.
 */
std::vector<unsigned char> ComputeSharedSecret(const SafePKey& myKeys, const SafePKey& peerPubKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(myKeys.get(), NULL);
    if (!ctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX for derivation");

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize derivation");
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerPubKey.get()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set peer public key");
    }

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to determine secret length");
    }

    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to derive secret");
    }

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

/**
 * @brief Generates a random polynomial mask from a ChaCha20 stream.
 */
DCRTPoly PRGToDCRTPoly(const std::vector<unsigned char>& seed, CryptoContext<DCRTPoly>& cc) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    
    // Use ChaCha20 to generate a stream of random bytes
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_chacha20();
    unsigned char key[32] = {0}; // 256-bit key
    unsigned char iv[16] = {0};  // 128-bit IV/nonce

    size_t len_to_copy = std::min(seed.size(), sizeof(key));
    std::copy(seed.begin(), seed.begin() + len_to_copy, key);

    size_t bytes_per_tower = params->GetRingDimension() * sizeof(uint64_t);
    size_t total_bytes = params->GetParams().size() * bytes_per_tower;
    std::vector<unsigned char> random_bytes(total_bytes);

    int out_len;
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, random_bytes.data(), &out_len, random_bytes.data(), random_bytes.size());
    EVP_CIPHER_CTX_free(ctx);

    // Create a DCRTPoly and fill it from the generated random bytes
    DCRTPoly random_poly(params, Format::EVALUATION, true);
    uint64_t* random_uints = reinterpret_cast<uint64_t*>(random_bytes.data());
    size_t uints_offset = 0;

    for (size_t i = 0; i < params->GetParams().size(); ++i) {
        // FIX: Create a NativeVector and populate it element-by-element
        // using the supported operator[] interface.
        NativeVector tower_vec(params->GetRingDimension(), params->GetParams()[i]->GetModulus());
        for (size_t j = 0; j < params->GetRingDimension(); ++j) {
            tower_vec[j] = random_uints[uints_offset + j];
        }

        // Wrap the now-populated vector in a NativePoly object.
        NativePoly tower_poly(params->GetParams()[i]);
        tower_poly.SetValues(std::move(tower_vec), Format::EVALUATION);

        // Set the correctly typed object in the DCRTPoly.
        random_poly.SetElementAtIndex(i, std::move(tower_poly));
        uints_offset += params->GetRingDimension();
    }
    return random_poly;
}


/**
 * @brief Generates the final additive mask for a client.
 */
DCRTPoly GenerateMask(uint32_t myId, const SafePKey& myKeys, 
                      const std::map<uint32_t, ECDHPublicKey>& allPublicKeys,
                      CryptoContext<DCRTPoly>& cc) {
    
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly final_mask(params, Format::EVALUATION, true); // Initialize to zero

    for (const auto& pair : allPublicKeys) {
        uint32_t peerId = pair.first;
        if (myId == peerId) continue;

        // Establish shared secret
        SafePKey peerPubKey = DeserializePublicKey(pair.second);
        std::vector<unsigned char> sharedSecret = ComputeSharedSecret(myKeys, peerPubKey);

        // Generate a random polynomial from the secret
        DCRTPoly p_ij = PRGToDCRTPoly(sharedSecret, cc);
        
        // Add or subtract based on ID to ensure masks sum to zero globally
        if (myId < peerId) {
            final_mask -= p_ij;
        } else {
            final_mask += p_ij;
        }
    }
    return final_mask;
}
