// server.cpp
//
// Implementation of the Server class, now with timing capabilities.

#include "server.h"
#include "mk_ckks.h" // Include the crypto engine

// A simple timer utility.
class Timer {
public:
    // Starts the timer.
    void Start() {
        m_StartTime = std::chrono::high_resolution_clock::now();
    }
    // Stops the timer and returns the duration in milliseconds.
    double Stop() {
        auto endTime = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = endTime - m_StartTime;
        return duration.count();
    }
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_StartTime;
};


Server::Server() {}

void Server::collectShare(const ClientShare& share) {
    m_clientShares.push_back(share);
}

// This function performs the homomorphic additions on the collected shares.
DCRTPoly Server::aggregateShares() {
    if (m_clientShares.empty()) {
        throw std::runtime_error("No client shares to aggregate.");
    }

    // Sum all the c0 components from each client's ciphertext.
    DCRTPoly result_c0 = m_clientShares[0].c0;
    for (size_t i = 1; i < m_clientShares.size(); ++i) {
        result_c0 += m_clientShares[i].c0;
    }

    // Sum all the masked d components from each client's share.
    // The masks are designed to sum to zero, leaving the sum of partial decryptions.
    DCRTPoly result_d_masked = m_clientShares[0].d_masked;
    for (size_t i = 1; i < m_clientShares.size(); ++i) {
        result_d_masked += m_clientShares[i].d_masked;
    }
    
    // The final raw polynomial is Sum(c0_i) + Sum(d_masked_i).
    // This is equivalent to Sum(c0_i + d_i), which decrypts to Sum(m_i).
    return result_c0 + result_d_masked;
}

// MODIFIED: The function now returns a ServerResult struct and measures performance.
ServerResult Server::getFinalResult(CryptoContext<DCRTPoly>& cc, uint32_t dataSize) {
    ServerResult result;
    Timer timer;

    // --- 1. Measure Share Aggregation Time (T_aggregate) ---
    timer.Start();
    DCRTPoly finalPoly = aggregateShares();
    result.timings.t_aggregate_ms = timer.Stop();
    // std::cout << "Server has aggregated all shares." << std::endl; // Moved to main loop

    // --- 2. Measure Final Decoding Time (T_decode) ---
    timer.Start();
    result.final_aggregated_vector = Decode(finalPoly, cc, dataSize);
    result.timings.t_decode_ms = timer.Stop();
    // std::cout << "Server has decoded the final result." << std::endl; // Moved to main loop
    
    return result;
}
