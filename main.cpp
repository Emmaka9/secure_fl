// main.cpp
//
// This is the main orchestrator for the secure aggregation simulation.
// It sets up the environment, creates clients and a server, directs the
// protocol flow, and verifies the final result. It also includes
// performance monitoring for key cryptographic operations.

#include "common.h"
#include "mk_ckks.h"
#include "client.h"
#include "server.h"

// Standard library includes for timing, file I/O, and calculations
#include <chrono>
#include <fstream>
#include <vector>
#include <numeric>
#include <algorithm>

int main() {
    std::cout << "🚀 Starting Secure Aggregation Simulation with Masking" << std::endl;

    // --- 1. SETUP ---
    std::cout << "\n--- Phase 1: Setup ---" << std::endl;
    uint32_t numClients = 100;
    uint32_t dataSize = 1024;

    // Configure CKKS parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(16384);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(dataSize);

    // Generate the crypto context
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    std::cout << "CryptoContext generated." << std::endl;

    // --- Performance Logging Setup ---
    std::ofstream logFile("timing_log.txt");
    logFile << "Client ID, KeyGen (us), Share-Gen (us)\n";
    std::vector<double> keygen_times;
    std::vector<double> share_gen_times;


    // --- 2. ROUND 1: Key Generation ---
    std::cout << "\n--- Phase 2 (Round 1): Key Generation ---" << std::endl;
    // The CRS 'a' is a public polynomial shared by all clients for key generation.
    DCRTPoly crs_a = GenerateCRS(cc);
    std::cout << "Common Reference String (CRS) generated." << std::endl;

    Server server;
    std::vector<Client> clients;
    clients.reserve(numClients);
    for (uint32_t i = 0; i < numClients; ++i) {
        // Time the creation of each client, which includes MK-CKKS and ECDH key generation.
        auto start_keygen = std::chrono::high_resolution_clock::now();
        clients.emplace_back(i, cc, crs_a);
        auto end_keygen = std::chrono::high_resolution_clock::now();
        
        // Record duration in microseconds
        double keygen_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_keygen - start_keygen).count();
        keygen_times.push_back(keygen_duration);
    }
    std::cout << numClients << " clients created and all keys generated." << std::endl;

    // --- New Step: Distribute ECDH Public Keys ---
    // In a real system, this would be a broadcast or a server-mediated exchange.
    std::map<uint32_t, ECDHPublicKey> allPublicKeys;
    for (const auto& client : clients) {
        allPublicKeys[client.getId()] = client.getECDHPublicKey();
    }
    std::cout << "ECDH public keys have been distributed to all clients." << std::endl;

    // --- 3. ROUND 2: Client-Side Computation ---
    std::cout << "\n--- Phase 3 (Round 2): Client Computation ---" << std::endl;
    for (auto& client : clients) {
        client.generateData(dataSize); // Generate random data vector

        // Time the client's share preparation. This includes:
        // 1. Mask generation (ECDH secret derivation and PRG).
        // 2. Data encoding and encryption (MK-CKKS Encrypt).
        // 3. Partial decryption calculation (`d_i = c1_i * s_i`).
        auto start_share = std::chrono::high_resolution_clock::now();
        ClientShare share = client.prepareShareForServer(cc, allPublicKeys);
        auto end_share = std::chrono::high_resolution_clock::now();
        
        // Record duration in microseconds
        double share_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_share - start_share).count();
        share_gen_times.push_back(share_duration);

        // Log the timing data for this client
        logFile << client.getId() << ", " << keygen_times[client.getId()] << ", " << share_duration << "\n";
        
        server.collectShare(share);
    }
    std::cout << "All clients have sent their secure shares to the server." << std::endl;

    // --- 4. ROUND 3: Server-Side Computation ---
    std::cout << "\n--- Phase 4 (Round 3): Server Computation ---" << std::endl;
    // Time the final aggregation and decoding on the server.
    auto start_decode = std::chrono::high_resolution_clock::now();
    std::vector<double> finalResult = server.getFinalResult(cc, dataSize);
    auto end_decode = std::chrono::high_resolution_clock::now();
    double decode_duration_ms = std::chrono::duration_cast<std::chrono::microseconds>(end_decode - start_decode).count() / 1000.0;
    logFile << "\nServer Final Decode Time (ms)," << decode_duration_ms << "\n";
    logFile.close();


    // --- 5. VERIFICATION ---
    std::cout << "\n--- Phase 5: Verification ---" << std::endl;
    // Calculate the expected sum locally for comparison.
    std::vector<double> expected_sum(dataSize, 0.0);
    for (const auto& client : clients) {
        const auto& clientData = client.getData();
        for (size_t i = 0; i < dataSize; ++i) {
            expected_sum[i] += clientData[i];
        }
    }

    // Determine the maximum error between the expected and actual result.
    double max_error = 0.0;
    for (size_t i = 0; i < dataSize; ++i) {
        double error = std::abs(expected_sum[i] - finalResult[i]);
        if (error > max_error) {
            max_error = error;
        }
    }

    // --- 6. Report Timings and Final Result ---
    std::cout << "\n--- Performance Summary ---" << std::endl;
    // Find the maximum time from all clients for each operation.
    double max_keygen_us = *std::max_element(keygen_times.begin(), keygen_times.end());
    double max_share_gen_us = *std::max_element(share_gen_times.begin(), share_gen_times.end());

    std::cout << "Max client key generation time: " << max_keygen_us / 1000.0 << " ms" << std::endl;
    std::cout << "Max client share generation time: " << max_share_gen_us / 1000.0 << " ms" << std::endl;
    std::cout << "Server final decode time: " << decode_duration_ms << " ms" << std::endl;
    std::cout << "Detailed timings logged to 'timing_log.txt'" << std::endl;

    std::cout << "\n--- Final Result ---" << std::endl;
    std::cout << std::fixed << std::setprecision(5);
    std::cout << "Maximum absolute error: " << max_error << std::endl;
    // Use a small tolerance for floating-point comparison.
    if (max_error < 0.001) {
        std::cout << "✅ SUCCESS: The final aggregated result is correct." << std::endl;
    } else {
        std::cout << "❌ FAILURE: The final result has a large error." << std::endl;
    }

    return 0;
}