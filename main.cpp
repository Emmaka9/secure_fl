// main.cpp
//
// This is the main orchestrator and a comprehensive EXPERIMENTAL HARNESS for the
// secure aggregation simulation. It is designed to run two distinct sets of
// experiments and measures both computational and communication costs.
//
// It logs all raw data points to dedicated CSV files for detailed analysis.

#include "common.h"
#include "mk_ckks.h"
#include "client.h"
#include "server.h"
#include <vector>
#include <memory>
#include <filesystem>
#include <sstream> // Required for serialization to in-memory streams



/**
 * @brief Calculates the smallest power of two that is greater than or equal to n.
 * This is crucial for determining the required batch size for the CKKS scheme,
 * which must be a power of two to support the underlying NTT/FFT operations.
 *
 * @param n The input data size.
 * @return uint32_t The next power of two.
 */
uint32_t next_power_of_2(uint32_t n) {
    // If n is already a power of two, we don't need to do anything.
    // The check (n & (n - 1)) == 0 is a standard bitwise trick to identify powers of two.
    if (n > 0 && (n & (n - 1)) == 0) {
        return n;
    }

    // This sequence of bitwise OR operations ensures that all bits to the right
    // of the most significant bit are set to 1.
    // For example, if n = 60000 (binary: 1110101001100000), this process
    // will transform it into 1111111111111111.
    n--; // Decrement n to handle the case where n is already a power of two.
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;

    // Incrementing the result gives us the next highest power of two.
    // For our example, this turns 1111111111111111 into 10000000000000000 (65536).
    n++;

    return n;
}

// =================================================================================
// EXPERIMENT CONFIGURATION
// =================================================================================

// --- Experiment 1: Scaling Number of Clients ---
const std::vector<int> CLIENT_COUNTS = {10, 50, 100, 200, 350};
const uint32_t FIXED_DATA_SIZE_FOR_EXP1 = 65536;

// --- Experiment 2: Scaling Data Size ---
const int FIXED_CLIENT_COUNT_FOR_EXP2 = 500;
const std::vector<uint32_t> DATA_SIZES = {4095, 8192, 16384, 32768, 50000, 65536};

// =================================================================================
// HELPER FUNCTIONS FOR COMMUNICATION COST MEASUREMENT
// =================================================================================

/**
 * @brief Measures the serialized size of a standard MKCiphertext (c0, c1).
 * This is used to calculate the ciphertext expansion factor.
 * @param cc The crypto context.
 * @param pk A client's public key, needed for the encryption operation.
 * @return The size of the serialized ciphertext in bytes.
 */
size_t get_mkciphertext_size(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a) {
    // Create a dummy zero plaintext for encryption
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly dummy_plaintext(params, Format::EVALUATION, true);
    MKeyGenKeyPair dummy_keys = KeyGenSingle(cc, crs_a);
    
    // Perform a standard encryption to get a representative ciphertext object.
    MKCiphertext ct = Encrypt(cc, dummy_keys.pk, dummy_keys.sk, dummy_plaintext);

    // Serialize the object into an in-memory stream and return its size.
    std::stringstream ss;
    lbcrypto::Serial::Serialize(ct.c0, ss, lbcrypto::SerType::BINARY);
    lbcrypto::Serial::Serialize(ct.c1, ss, lbcrypto::SerType::BINARY);
    return ss.str().size();
}



/**
 * @brief Measures the serialized size of the ClientShare object (c0, d_masked).
 * This represents the true client uplink communication cost.
 * @param share The ClientShare object to measure.
 * @return The size of the serialized share in bytes.
 */
size_t get_client_share_size(const ClientShare& share) {
    std::stringstream ss;
    lbcrypto::Serial::Serialize(share.c0, ss, lbcrypto::SerType::BINARY);
    lbcrypto::Serial::Serialize(share.d_masked, ss, lbcrypto::SerType::BINARY);
    return ss.str().size();
}

// =================================================================================
// FORWARD DECLARATION of the main experiment runner function
// =================================================================================
void run_experiment(const std::string& experiment_name,
                      int numClients, uint32_t dataSize,
                      std::ofstream& compute_client_log, std::ofstream& compute_server_log,
                      std::ofstream& comm_log);




// // +++++++++++++++++++++++ Verification ++++++++++++++++++++++++++++++++
// // =================================================================================
// // MAIN ORCHESTRATOR (MODIFIED FOR A SINGLE TEST RUN)
// // =================================================================================

// int main() {
//     std::cout << "🚀 Starting Secure Aggregation Performance Evaluation Harness" << std::endl;
//     std::cout << "--- RUNNING IN SINGLE TEST MODE ---" << std::endl;

//     // --- Setup Log Directory (No changes here) ---
//     std::string log_dir = "../log_files";
//     try {
//         std::filesystem::create_directory(log_dir);
//     } catch (const std::filesystem::filesystem_error& e) {
//         std::cerr << "Error creating log directory: " << e.what() << std::endl;
//         return 1;
//     }

//     // --- Setup Log Files (No changes here) ---
//     std::ofstream compute_client_log(log_dir + "/log_computation_client.csv");
//     compute_client_log << "Experiment,NumClients,DataSize,RingDimension,ClientID,T_KeyGen_MKCKKS_ms,T_KeyGen_ECDH_ms,T_KeyGen_Total_ms,T_Encrypt_ms,T_MaskGen_ms,T_ClientTotal_ms\n";
    
//     std::ofstream compute_server_log(log_dir + "/log_computation_server.csv");
//     compute_server_log << "Experiment,NumClients,DataSize,RingDimension,T_Aggregate_ms,T_Decode_ms,T_ServerTotal_ms\n";

//     std::ofstream comm_log(log_dir + "/log_communication_analysis.csv");
//     comm_log << "Experiment,NumClients,DataSize,RingDimension,PlaintextBytes,CiphertextBytes,ClientUplinkBytes,SetupBytes,FinalDownlinkBytes,CiphertextExpansion,CommExpansion\n";

//     // ============================================================================
//     // --- SINGLE TEST RUN ---
//     // The original experiment loops are commented out for this test.
//     // ============================================================================

//     std::cout << "\n\n=================================================================================="
//               << "\n--- VERIFICATION TEST: Running a single demanding experiment ---"
//               << "\n==================================================================================" << std::endl;
    
//     // We are calling run_experiment directly, now including the required experiment_name parameter.
//     run_experiment("VerificationTest", 500, 131072, 262144, compute_client_log, compute_server_log, comm_log);

//     /*
//     // --- EXPERIMENT 1: SCALING NUMBER OF CLIENTS --- (Commented out)
//     for (int numClients : CLIENT_COUNTS) {
//         run_experiment("ScalingClients", numClients, FIXED_DATA_SIZE_FOR_EXP1, FIXED_RING_DIM_FOR_EXP1, compute_client_log, compute_server_log, comm_log);
//     }

//     // --- EXPERIMENT 2: SCALING DATA SIZE --- (Commented out)
//     for (size_t i = 0; i < DATA_SIZES.size(); ++i) {
//         run_experiment("ScalingDataSize", FIXED_CLIENT_COUNT_FOR_EXP2, DATA_SIZES[i], RING_DIMENSIONS[i], compute_client_log, compute_server_log, comm_log);
//     }
//     */

//     // --- Cleanup ---
//     compute_client_log.close();
//     compute_server_log.close();
//     comm_log.close();

//     std::cout << "\n\n🎉 Test run finished successfully!" << std::endl;
//     std::cout << "Please check the 'log_files' directory and console output for verification." << std::endl;
    
//     return 0;
// }

// //++++++++++++++++++++++ End Verification ++++++++++++++++++++++++++






// =================================================================================
// MAIN ORCHESTRATOR
// =================================================================================

int main() {
    std::cout << "🚀 Starting Secure Aggregation Performance Evaluation Harness" << std::endl;

    // --- Setup Log Directory ---
    std::string log_dir = "../log_files";
    try {
        std::filesystem::create_directory(log_dir);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating log directory: " << e.what() << std::endl;
        return 1;
    }

    // --- Setup Log Files ---
    std::ofstream compute_client_log(log_dir + "/log_computation_client.csv");
    compute_client_log << "Experiment,NumClients,DataSize,RingDimension,ClientID,T_KeyGen_MKCKKS_ms,T_KeyGen_ECDH_ms,T_KeyGen_Total_ms,T_Encrypt_ms,T_MaskGen_ms,T_ClientTotal_ms\n";
    
    std::ofstream compute_server_log(log_dir + "/log_computation_server.csv");
    compute_server_log << "Experiment,NumClients,DataSize,RingDimension,T_Aggregate_ms,T_Decode_ms,T_ServerTotal_ms\n";

    std::ofstream comm_log(log_dir + "/log_communication_analysis.csv");
    comm_log << "Experiment,NumClients,DataSize,RingDimension,PlaintextBytes,CiphertextBytes,ClientUplinkBytes,SetupBytes,FinalDownlinkBytes,CiphertextExpansion,CommExpansion\n";

    // ============================================================================
    // --- EXPERIMENT 1: SCALING NUMBER OF CLIENTS ---
    // ============================================================================
    std::cout << "\n\n=================================================================================="
              << "\n--- EXPERIMENT 1: SCALING NUMBER OF CLIENTS (Data Size = " << FIXED_DATA_SIZE_FOR_EXP1 << ") ---"
              << "\n==================================================================================" << std::endl;
    
    for (int numClients : CLIENT_COUNTS) {
        // Call run_experiment with the explicit name for this experiment.
        run_experiment("ScalingClients", numClients, FIXED_DATA_SIZE_FOR_EXP1, compute_client_log, compute_server_log, comm_log);
    }

    // ============================================================================
    // --- EXPERIMENT 2: SCALING DATA SIZE ---
    // ============================================================================
    std::cout << "\n\n============================================================================"
              << "\n--- EXPERIMENT 2: SCALING DATA SIZE (Client Count = " << FIXED_CLIENT_COUNT_FOR_EXP2 << ") ---"
              << "\n============================================================================" << std::endl;

    for (size_t i = 0; i < DATA_SIZES.size(); ++i) {
        // Call run_experiment with the explicit name for this experiment.
        run_experiment("ScalingDataSize", FIXED_CLIENT_COUNT_FOR_EXP2, DATA_SIZES[i], compute_client_log, compute_server_log, comm_log);
    }

    // --- Cleanup ---
    compute_client_log.close();
    compute_server_log.close();
    comm_log.close();

    std::cout << "\n\n🎉 All experiments finished successfully!" << std::endl;
    std::cout << "Raw data for all runs has been logged to the 'log_files' directory." << std::endl;
    
    return 0;
}







// =================================================================================
// CORE EXPERIMENT RUNNER FUNCTION
// =================================================================================
void run_experiment(const std::string& experiment_name, int numClients, uint32_t dataSize, 
                      std::ofstream& compute_client_log,
                      std::ofstream& compute_server_log, 
                      std::ofstream& comm_log) {

    uint32_t batchSize = next_power_of_2(dataSize);
    uint32_t ringDimension;
    if (batchSize < 16384){
        ringDimension = 16384;
    }
    else{
        ringDimension = 2 * batchSize;
    }
    
    std::cout << "\n--- Running " << experiment_name 
              << " with N=" << numClients << ", d=" << dataSize 
              << ", N_poly=" << ringDimension << " ---" << std::endl;
    
    // --- A. Per-Run CryptoContext Generation ---
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(ringDimension);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);

    // --- B. Setup: Create Clients, Server, and Generate All Keys ---
    DCRTPoly crs_a = GenerateCRS(cc);
    Server server;
    std::vector<Client> clients;
    clients.reserve(numClients);
    
    std::cout << "Generating keys for all " << numClients << " clients..." << std::endl;
    for (int i = 0; i < numClients; ++i) {
        clients.emplace_back(i);
        clients[i].generateKeys(cc, crs_a);
    }
    
    std::map<uint32_t, ECDHPublicKey> allPublicKeys;
    for (const auto& client : clients) {
        allPublicKeys[client.getId()] = client.getECDHPublicKey();
    }
    std::cout << "Setup and KeyGen complete." << std::endl;

    ClientShare representative_share;
    ClientTimings last_client_timings;

    // --- C & F. STREAMING: Process, Aggregate, and Log One Client at a Time ---
    for (int i = 0; i < numClients; ++i) {
        clients[i].generateData(dataSize, -999.0, 999.0);
        ClientResult client_result = clients[i].prepareShareForServer(cc, allPublicKeys);
        server.collectShare(client_result.share);
        
        if (i == 0) {
            representative_share = client_result.share;
        }

        last_client_timings = client_result.timings;
        
        // Log timing data using the explicit experiment_name.
        compute_client_log << experiment_name << "," << numClients << "," << dataSize << "," << ringDimension << "," << i << ","
                             << last_client_timings.key_gen.t_mkckks_ms << ","
                             << last_client_timings.key_gen.t_ecdh_ms << ","
                             << last_client_timings.key_gen.t_total_ms << ","
                             << last_client_timings.t_encrypt_ms << ","
                             << last_client_timings.t_mask_gen_ms << ","
                             << last_client_timings.t_client_total_ms << std::endl;
    }
    std::cout << "All clients have prepared and sent shares." << std::endl;

    // --- D. Server-Side Computation & Timing ---
    ServerResult server_result = server.getFinalResult(cc, dataSize);
    server_result.timings.t_server_total_ms = server_result.timings.t_aggregate_ms + server_result.timings.t_decode_ms;
    std::cout << "Server has aggregated and decoded the final result." << std::endl;

    // --- E. COMMUNICATION COST ANALYSIS ---
    size_t plaintext_bytes = dataSize * sizeof(double);
    size_t ciphertext_bytes = get_mkciphertext_size(cc, crs_a);
    size_t client_uplink_bytes = get_client_share_size(representative_share);
    size_t setup_bytes = 0;

    for (const auto& pair : allPublicKeys) {
        setup_bytes += pair.second.size();
    }

    size_t final_downlink_bytes = server_result.final_aggregated_vector.size() * sizeof(double);
    double ciphertext_expansion = (double)ciphertext_bytes / plaintext_bytes;
    size_t total_secure_comm_per_client = (setup_bytes / numClients) + client_uplink_bytes + (final_downlink_bytes / numClients);
    double comm_expansion = (double)total_secure_comm_per_client / plaintext_bytes;

    // --- F. LOGGING (Server and Communication logs) ---
    compute_server_log << experiment_name << "," << numClients << "," << dataSize << "," << ringDimension << ","
                       << server_result.timings.t_aggregate_ms << ","
                       << server_result.timings.t_decode_ms << ","
                       << server_result.timings.t_server_total_ms << std::endl;

    comm_log << experiment_name << "," << numClients << "," << dataSize << "," << ringDimension << ","
             << plaintext_bytes << "," << ciphertext_bytes << "," << client_uplink_bytes << ","
             << setup_bytes << "," << final_downlink_bytes << ","
             << ciphertext_expansion << "," << comm_expansion << std::endl;
    
    // --- G. CONSOLE SUMMARY ---
    std::cout << "  Computation Summary (Last Client):\n"
              << "    - T_Encrypt: " << last_client_timings.t_encrypt_ms << " ms\n"
              << "    - T_MaskGen: " << last_client_timings.t_mask_gen_ms << " ms\n";
    std::cout << "  Communication Cost Summary:\n"
              << "    - Client Uplink Share Size: " << (client_uplink_bytes / 1024.0) << " KB\n"
              << "    - Ciphertext Expansion Factor: " << std::fixed << std::setprecision(2) << ciphertext_expansion << "x\n"
              << "    - Communication Expansion Factor: " << comm_expansion << "x\n";
}