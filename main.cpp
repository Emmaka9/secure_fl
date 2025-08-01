// main.cpp
//
// This is the main orchestrator and a comprehensive EXPERIMENTAL HARNESS for the
// secure aggregation simulation. It is designed to run two distinct sets of
// experiments:
//   1. Scaling the number of clients (N) with a fixed data size.
//   2. Scaling the data size (d) with a fixed number of clients.
//
// It measures granular performance metrics for each cryptographic stage and
// prints formatted summary tables to the console, while logging all raw data
// points to four separate, clearly-named CSV files for detailed analysis.

#include "common.h"
#include "mk_ckks.h"
#include "client.h"
#include "server.h"
#include <vector>
#include <memory>
#include <filesystem>

// =================================================================================
// EXPERIMENT CONFIGURATION (LARGE-SCALE)
// =================================================================================

// --- Experiment 1: Scaling Number of Clients ---
// More data points, up to 500 clients.
const std::vector<int> CLIENT_COUNTS = {10, 50, 100, 200, 500};
// FIX: Data vector size must be a power of two. Using 2^16 = 65536.
const uint32_t FIXED_DATA_SIZE_FOR_EXP1 = 65536;
// Ring dimension must be a power of 2 and >= 2 * dataSize. 2^18 = 262144 is appropriate.
const uint32_t FIXED_RING_DIM_FOR_EXP1 = 131072; 

// --- Experiment 2: Scaling Data Size ---
// Number of clients is now fixed at 500.
const int FIXED_CLIENT_COUNT_FOR_EXP2 = 500;
// Testing a wider range of data sizes.
const std::vector<uint32_t> DATA_SIZES = {4096, 8192, 16384, 32768, 65536};
// Corresponding ring dimensions. Each must be a power of 2, meet the security
// standard (>=16384), and be >= 2 * dataSize.
const std::vector<uint32_t> RING_DIMENSIONS = {16384, 16384, 32768, 65536, 131072};


// =================================================================================
// FORWARD DECLARATION of the main experiment runner function
// =================================================================================
void run_experiment(int numClients, uint32_t dataSize, uint32_t ringDimension,
                    std::ofstream& client_log, std::ofstream& server_log);


// =================================================================================
// MAIN ORCHESTRATOR
// =================================================================================

int main() {
    std::cout << "🚀 Starting Secure Aggregation Performance Evaluation Harness (Large-Scale)" << std::endl;

    // --- Setup Log Directory ---
    std::string log_dir = "../log_files";
    try {
        std::filesystem::create_directory(log_dir);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating log directory: " << e.what() << std::endl;
        return 1;
    }

    // ============================================================================
    // --- EXPERIMENT 1: SCALING NUMBER OF CLIENTS ---
    // ============================================================================
    std::cout << "\n\n=================================================================================="
              << "\n--- EXPERIMENT 1: SCALING NUMBER OF CLIENTS (Data Size = " << FIXED_DATA_SIZE_FOR_EXP1 << ") ---"
              << "\n==================================================================================" << std::endl;

    // --- Setup Log Files for Experiment 1 ---
    std::ofstream client_log_exp1(log_dir + "/log_scaling_clients_client.csv");
    client_log_exp1 << "NumClients,DataSize,RingDimension,ClientID,T_KeyGen_MKCKKS_ms,T_KeyGen_ECDH_ms,T_KeyGen_Total_ms,T_Encrypt_ms,T_PartialDec_ms,T_MaskGen_ms,T_ClientTotal_ms\n";
    
    std::ofstream server_log_exp1(log_dir + "/log_scaling_clients_server.csv");
    server_log_exp1 << "NumClients,DataSize,RingDimension,T_Aggregate_ms,T_Decode_ms,T_ServerTotal_ms\n";

    // --- Run Experiment 1 Loop ---
    for (int numClients : CLIENT_COUNTS) {
        run_experiment(numClients, FIXED_DATA_SIZE_FOR_EXP1, FIXED_RING_DIM_FOR_EXP1, client_log_exp1, server_log_exp1);
    }
    client_log_exp1.close();
    server_log_exp1.close();


    // ============================================================================
    // --- EXPERIMENT 2: SCALING DATA SIZE ---
    // ============================================================================
    std::cout << "\n\n============================================================================"
              << "\n--- EXPERIMENT 2: SCALING DATA SIZE (Client Count = " << FIXED_CLIENT_COUNT_FOR_EXP2 << ") ---"
              << "\n============================================================================" << std::endl;

    // --- Setup Log Files for Experiment 2 ---
    std::ofstream client_log_exp2(log_dir + "/log_scaling_datasize_client.csv");
    client_log_exp2 << "NumClients,DataSize,RingDimension,ClientID,T_KeyGen_MKCKKS_ms,T_KeyGen_ECDH_ms,T_KeyGen_Total_ms,T_Encrypt_ms,T_PartialDec_ms,T_MaskGen_ms,T_ClientTotal_ms\n";
    
    std::ofstream server_log_exp2(log_dir + "/log_scaling_datasize_server.csv");
    server_log_exp2 << "NumClients,DataSize,RingDimension,T_Aggregate_ms,T_Decode_ms,T_ServerTotal_ms\n";

    // --- Run Experiment 2 Loop ---
    for (size_t i = 0; i < DATA_SIZES.size(); ++i) {
        run_experiment(FIXED_CLIENT_COUNT_FOR_EXP2, DATA_SIZES[i], RING_DIMENSIONS[i], client_log_exp2, server_log_exp2);
    }
    client_log_exp2.close();
    server_log_exp2.close();


    std::cout << "\n\n🎉 All experiments finished successfully!" << std::endl;
    std::cout << "Raw data for all runs has been logged to the 'log_files' directory." << std::endl;
    
    return 0;
}


// =================================================================================
// CORE EXPERIMENT RUNNER FUNCTION
// =================================================================================

/**
 * @brief Executes a single, complete performance evaluation run for a given set
 * of parameters. It handles crypto context generation, client/server setup,
 * all cryptographic operations, timing, and logging.
 *
 * @param numClients The number of clients (N) for this run.
 * @param dataSize The size of the data vector (d) for each client.
 * @param ringDimension The polynomial ring dimension (N_poly) for CKKS.
 * @param client_log An output file stream for logging detailed client metrics.
 * @param server_log An output file stream for logging server metrics.
 */
void run_experiment(int numClients, uint32_t dataSize, uint32_t ringDimension,
                    std::ofstream& client_log, std::ofstream& server_log) {
    
    std::cout << "\n--- Running with N=" << numClients << ", d=" << dataSize << ", N_poly=" << ringDimension << " ---" << std::endl;

    // --- A. Per-Run CryptoContext Generation ---
    // This is critical because the context depends on the data/ring size.
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(ringDimension);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);

    parameters.SetBatchSize(dataSize);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    //cc->Enable(KEYSWITCH);
    //cc->Enable(LEVELEDSHE);

    // --- B. Setup & Key Generation Timing ---
    DCRTPoly crs_a = GenerateCRS(cc);
    Server server;
    std::vector<Client> clients;
    clients.reserve(numClients);
    std::vector<ClientTimings> allClientTimings(numClients);

    for (int i = 0; i < numClients; ++i) {
        clients.emplace_back(i);
        clients[i].generateKeys(cc, crs_a, allClientTimings[i].key_gen);
    }
    
    std::map<uint32_t, ECDHPublicKey> allPublicKeys;
    for (const auto& client : clients) {
        allPublicKeys[client.getId()] = client.getECDHPublicKey();
    }
    std::cout << "Setup and KeyGen complete." << std::endl;

    // --- C. Client-Side Round Computation & Timing ---
    for (int i = 0; i < numClients; ++i) {
        clients[i].generateData(dataSize);
        ClientResult client_result = clients[i].prepareShareForServer(cc, allPublicKeys);
        server.collectShare(client_result.share);
        allClientTimings[i].t_encrypt_ms = client_result.timings.t_encrypt_ms;
        allClientTimings[i].t_partial_dec_ms = client_result.timings.t_partial_dec_ms;
        allClientTimings[i].t_mask_gen_ms = client_result.timings.t_mask_gen_ms;
        allClientTimings[i].t_client_total_ms = client_result.timings.t_client_total_ms;
    }
    std::cout << "All clients have prepared and sent shares." << std::endl;

    // --- D. Server-Side Computation & Timing ---
    ServerResult server_result = server.getFinalResult(cc, dataSize);
    server_result.timings.t_server_total_ms = server_result.timings.t_aggregate_ms + server_result.timings.t_decode_ms;
    std::cout << "Server has aggregated and decoded the final result." << std::endl;

    // --- E. Log Raw Data to CSV ---
    // The data is written in a consistent order for all experiments.
    for(int i = 0; i < numClients; ++i) {
        client_log << numClients << "," << dataSize << "," << ringDimension << "," << i << ","
                   << allClientTimings[i].key_gen.t_mkckks_ms << ","
                   << allClientTimings[i].key_gen.t_ecdh_ms << ","
                   << allClientTimings[i].key_gen.t_total_ms << ","
                   << allClientTimings[i].t_encrypt_ms << ","
                   << allClientTimings[i].t_partial_dec_ms << ","
                   << allClientTimings[i].t_mask_gen_ms << ","
                   << allClientTimings[i].t_client_total_ms << "\n";
    }
    server_log << numClients << "," << dataSize << "," << ringDimension << ","
               << server_result.timings.t_aggregate_ms << ","
               << server_result.timings.t_decode_ms << ","
               << server_result.timings.t_server_total_ms << "\n";
    
    // NOTE: Console printing is omitted here to keep the main loop clean.
    // The focus is on generating the comprehensive CSV logs.
}
