// main.cpp
//
// This is the main orchestrator for the secure aggregation simulation.
// It sets up the environment, creates clients and a server, directs the
// protocol flow, and verifies the final result.

#include "common.h"
#include "mk_ckks.h"
#include "client.h"
#include "server.h"

int main() {
    std::cout << "🚀 Starting Secure Aggregation Simulation with Masking" << std::endl;

    // --- 1. SETUP ---
    std::cout << "\n--- Phase 1: Setup ---" << std::endl;
    uint32_t numClients = 10;
    uint32_t dataSize = 128;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(16384);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(dataSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    std::cout << "CryptoContext generated." << std::endl;

    // --- 2. ROUND 1: Key Generation ---
    std::cout << "\n--- Phase 2 (Round 1): Key Generation ---" << std::endl;
    DCRTPoly crs_a = GenerateCRS(cc);
    std::cout << "Common Reference String (CRS) generated." << std::endl;

    Server server;
    std::vector<Client> clients;
    clients.reserve(numClients);
    for (uint32_t i = 0; i < numClients; ++i) {
        clients.emplace_back(i, cc, crs_a);
    }
    std::cout << numClients << " clients created and all keys generated." << std::endl;

    // --- New Step: Distribute ECDH Public Keys ---
    std::map<uint32_t, ECDHPublicKey> allPublicKeys;
    for (const auto& client : clients) {
        allPublicKeys[client.getId()] = client.getECDHPublicKey();
    }
    std::cout << "ECDH public keys have been distributed to all clients." << std::endl;

    // --- 3. ROUND 2: Client-Side Computation ---
    std::cout << "\n--- Phase 3 (Round 2): Client Computation ---" << std::endl;
    for (auto& client : clients) {
        client.generateData(dataSize);
        ClientShare share = client.prepareShareForServer(cc, allPublicKeys);
        server.collectShare(share);
    }
    std::cout << "All clients have sent their secure shares to the server." << std::endl;

    // --- 4. ROUND 3: Server-Side Computation ---
    std::cout << "\n--- Phase 4 (Round 3): Server Computation ---" << std::endl;
    std::vector<double> finalResult = server.getFinalResult(cc, dataSize);

    // --- 5. VERIFICATION ---
    std::cout << "\n--- Phase 5: Verification ---" << std::endl;
    std::vector<double> expected_sum(dataSize, 0.0);
    for (const auto& client : clients) {
        const auto& clientData = client.getData();
        for (size_t i = 0; i < dataSize; ++i) {
            expected_sum[i] += clientData[i];
        }
    }

    double max_error = 0.0;
    for (size_t i = 0; i < dataSize; ++i) {
        double error = std::abs(expected_sum[i] - finalResult[i]);
        if (error > max_error) {
            max_error = error;
        }
    }

    std::cout << std::fixed << std::setprecision(5);
    std::cout << "Maximum absolute error: " << max_error << std::endl;
    if (max_error < 0.001) {
        std::cout << "✅ SUCCESS: The final aggregated result is correct." << std::endl;
    } else {
        std::cout << "❌ FAILURE: The final result has a large error." << std::endl;
    }

    return 0;
}
