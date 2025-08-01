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
void Client::generateKeys(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a, KeyGenTimings& timings) {
    Timer timer;
    timer.Start();
    m_keys = KeyGenSingle(cc, crs_a);
    timings.t_mkckks_ms = timer.Stop();
    timer.Start();
    m_ecdhKeys = GenerateECDHKeys();
    timings.t_ecdh_ms = timer.Stop();
    timings.t_total_ms = timings.t_mkckks_ms + timings.t_ecdh_ms;
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

    // 1. Measure Encoding and the new combined Encryption step.
    timer.Start();
    DCRTPoly encoded_poly = encodeVector(cc, m_data);
    // MODIFIED: Call the updated Encrypt function, passing the secret key as well.
    MKCiphertext ciphertext = Encrypt(cc, m_keys.pk, m_keys.sk, encoded_poly);
    result.timings.t_encrypt_ms = timer.Stop();
    
    // 2. Measure Mask Generation Time.
    timer.Start();
    DCRTPoly mask = GenerateMask(m_id, m_ecdhKeys, allPublicKeys, cc);
    result.timings.t_mask_gen_ms = timer.Stop();

    // 3. Apply the mask and create the final share.
    result.share.c0 = ciphertext.c0;
    // The second component of the ciphertext (c1) is now the partial decryption share 'd'.
    // We add the mask to it to get the final d_masked.
    result.share.d_masked = ciphertext.c1 + mask;

    // 4. Calculate total client-side time for this round.
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
