// client.cpp
//
// Implementation of the Client class, now with refactored key generation.

#include "client.h"
#include "mk_ckks.h" // Include the crypto engine
#include "masking.h" // Include the new masking engine

// A simple timer utility.
class Timer {
public:
    void Start() { m_StartTime = std::chrono::high_resolution_clock::now(); }
    double Stop() {
        auto endTime = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(endTime - m_StartTime).count();
    }
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_StartTime;
};

// Constructor is now lightweight.
Client::Client(uint32_t id) : m_id(id) {}

// Key generation is now an explicit, timed function.
// MODIFIED: This function now populates the internal m_keyGenTimings member variable.
void Client::generateKeys(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a) {
    Timer timer;
    timer.Start();
    m_keys = KeyGenSingle(cc, crs_a);
    // Store the result in our new member variable.
    m_keyGenTimings.t_mkckks_ms = timer.Stop();

    timer.Start();
    m_ecdhKeys = GenerateECDHKeys();
    // Store the result in our new member variable.
    m_keyGenTimings.t_ecdh_ms = timer.Stop();

    m_keyGenTimings.t_total_ms = m_keyGenTimings.t_mkckks_ms + m_keyGenTimings.t_ecdh_ms;
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

// This function implements the full client-side protocol for a single round.
ClientResult Client::prepareShareForServer(CryptoContext<DCRTPoly>& cc, const std::map<uint32_t, ECDHPublicKey>& allPublicKeys) {

    ClientResult result;
    Timer timer;

    // MODIFIED: Before doing anything else, copy the stored keygen timings into the result.
    // This ensures every ClientResult has the complete timing information.
    result.timings.key_gen = m_keyGenTimings;



    // 1. Measure Encoding and Encryption.
    timer.Start();
    DCRTPoly encoded_poly = encodeVector(cc, m_data);
    MKCiphertext ciphertext = Encrypt(cc, m_keys.pk, m_keys.sk, encoded_poly);
    result.timings.t_encrypt_ms = timer.Stop();


    // 2. Measure Mask Generation Time.
    timer.Start();
    DCRTPoly mask = GenerateMask(m_id, m_ecdhKeys, allPublicKeys, cc);
    result.timings.t_mask_gen_ms = timer.Stop();


    // 3. Apply the mask and create the final share.
    result.share.c0 = ciphertext.c0;
    result.share.d_masked = ciphertext.c1 + mask;

    // 4. Calculate total client-side time.
    result.timings.t_client_total_ms = result.timings.t_encrypt_ms + result.timings.t_mask_gen_ms;

    return result;
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
