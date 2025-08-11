// // test_debug.cpp
// //
// // A dedicated debugging tool to investigate the mask cancellation property of the
// // secure aggregation protocol. This program isolates the mask generation logic
// // to verify if the sum of all client masks correctly cancels out to zero.

// #include "common.h"
// #include "mk_ckks.h"
// #include "client.h"
// #include "masking.h" // We need direct access to the masking engine

// int main() {
//     std::cout << "🚀 Starting Mask Cancellation Debug Test" << std::endl;

//     // --- 1. SETUP ---
//     // Use the same parameters as the main application for a consistent test.
//     std::cout << "\n--- Phase 1: Setup ---" << std::endl;
//     uint32_t numClients = 10;
//     uint32_t dataSize = 128;

//     CCParams<CryptoContextCKKSRNS> parameters;
//     parameters.SetRingDim(16384);
//     parameters.SetMultiplicativeDepth(1);
//     parameters.SetScalingModSize(50);
//     parameters.SetBatchSize(dataSize);

//     CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
//     cc->Enable(PKE);
//     std::cout << "CryptoContext generated." << std::endl;

//     // --- 2. KEY GENERATION & DISTRIBUTION ---
//     std::cout << "\n--- Phase 2: Key Generation & Distribution ---" << std::endl;
//     DCRTPoly crs_a = GenerateCRS(cc);
//     std::cout << "Common Reference String (CRS) generated." << std::endl;

//     // Create clients, which generate their own MK-CKKS and ECDH keys.
//     std::vector<Client> clients;
//     clients.reserve(numClients);
//     for (uint32_t i = 0; i < numClients; ++i) {
//         clients.emplace_back(i, cc, crs_a);
//     }
//     std::cout << numClients << " clients created and all keys generated." << std::endl;

//     // Distribute the ECDH public keys, which are needed for mask generation.
//     std::map<uint32_t, ECDHPublicKey> allPublicKeys;
//     for (const auto& client : clients) {
//         allPublicKeys[client.getId()] = client.getECDHPublicKey();
//     }
//     std::cout << "ECDH public keys have been distributed." << std::endl;

//     // --- 3. MASK GENERATION & SUMMATION ---
//     std::cout << "\n--- Phase 3: Generating and Summing Masks ---" << std::endl;
    
//     // Create a polynomial to hold the sum of all masks, initialized to zero.
//     auto params = cc->GetCryptoParameters()->GetElementParams();
//     DCRTPoly sum_of_masks(params, Format::EVALUATION, true);

//     // This is a simplified simulation of each client generating its mask.
//     // To do this properly without exposing private keys, we'd need to refactor the Client class.
//     // For this debug script, we'll mimic the process.
//     // NOTE: This part of the debug script is not perfectly realistic as it re-generates keys.
//     // The purpose is to test the GenerateMask function's cancellation property.
//     std::vector<SafePKey> client_ecdh_keys;
//     client_ecdh_keys.reserve(numClients);
//     for(uint32_t i = 0; i < numClients; ++i) {
//         client_ecdh_keys.push_back(GenerateECDHKeys());
//         allPublicKeys[i] = SerializePublicKey(client_ecdh_keys[i]);
//     }
    
//     for (uint32_t i = 0; i < numClients; ++i) {
//         std::cout << "Generating mask for client " << i << "..." << std::endl;
//         DCRTPoly mask = GenerateMask(i, client_ecdh_keys[i], allPublicKeys, cc);
//         sum_of_masks += mask;
//     }

//     // --- 4. VERIFICATION ---
//     std::cout << "\n--- Phase 4: Verification ---" << std::endl;
    
//     // FIX: The .Norm() method internally calls CRTInterpolate, which requires
//     // the polynomial to be in COEFFICIENT format. We must switch formats before calling it.
//     sum_of_masks.SwitchFormat();

//     // The infinity norm of a polynomial is the largest absolute value of its coefficients.
//     // If the polynomial is truly zero, its norm will be 0.
//     double norm = sum_of_masks.Norm();

//     std::cout << std::fixed << std::setprecision(1);
//     std::cout << "Infinity norm of the summed masks: " << norm << std::endl;

//     if (norm < 1e-6) { // Use a small tolerance for floating point comparisons
//         std::cout << "\n✅ SUCCESS: The masks correctly cancel out to zero." << std::endl;
//         std::cout << "The problem is likely not in the cancellation logic itself." << std::endl;
//     } else {
//         std::cout << "\n❌ FAILURE: The masks DO NOT cancel out to zero." << std::endl;
//         std::cout << "This confirms the random polynomials being generated for the masks have coefficients that are too large, causing overflow and noise issues." << std::endl;
//     }

//     return 0;
// }
