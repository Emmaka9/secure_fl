// client.cpp
//
// Implementation of the Client class, now with masking capabilities.

#include "client.h"
#include "mk_ckks.h" // Include the crypto engine
#include "masking.h" // Include the new masking engine

Client::Client(uint32_t id, CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a) : m_id(id) {
    // The client generates its own keys upon creation.
    m_keys = KeyGenSingle(cc, crs_a);
    m_ecdhKeys = GenerateECDHKeys();
}

void Client::generateData(uint32_t dataSize, double minVal, double maxVal) {
    m_data.resize(dataSize);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> distrib(minVal, maxVal);
    for (uint32_t i = 0; i < dataSize; ++i) {
        m_data[i] = distrib(gen);
    }
}

// FIX: The function signature now correctly matches the declaration in client.h
ClientShare Client::prepareShareForServer(CryptoContext<DCRTPoly>& cc, const std::map<uint32_t, ECDHPublicKey>& allPublicKeys) {
    // 1. Encode and Encrypt the data as before.
    DCRTPoly encoded_poly = encodeVector(cc, m_data);
    MKCiphertext ciphertext = Encrypt(cc, m_keys.pk, encoded_poly);

    // 2. Compute the unmasked partial decryption polynomial.
    // FIX: Call the correctly renamed function 'ComputePartialDecryption'.
    DCRTPoly partial_decryption = ComputePartialDecryption(cc, m_keys.sk, ciphertext);
    
    // 3. Generate the privacy-preserving mask.
    DCRTPoly mask = GenerateMask(m_id, m_ecdhKeys, allPublicKeys, cc);

    // 4. Apply the mask and create the final share to be sent.
    ClientShare final_share;
    final_share.c0 = ciphertext.c0;
    // FIX: Add the raw partial decryption polynomial to the mask.
    final_share.d_masked = partial_decryption + mask;
    
    std::cout << "Client " << m_id << " has prepared its SECURE share." << std::endl;
    return final_share;
}

uint32_t Client::getId() const {
    return m_id;
}

const std::vector<double>& Client::getData() const {
    return m_data;
}

ECDHPublicKey Client::getECDHPublicKey() const {
    return SerializePublicKey(m_ecdhKeys);
}
