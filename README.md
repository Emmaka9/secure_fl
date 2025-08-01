# Secure Aggregation Simulator for Federated Learning

This project is a C++ simulation of a secure aggregation protocol for federated learning (FL). It demonstrates how multiple clients can collaboratively compute the sum of their private data vectors without revealing them to a central server or to each other. The protocol combines Multi-Key Homomorphic Encryption (MKHE) based on the CKKS scheme with an additive secret-sharing mask to ensure privacy.

The simulation is built using the **OpenFHE** library for homomorphic encryption and **OpenSSL** for cryptographic primitives used in the masking scheme. It is optimized for performance using **OpenMP** to parallelize client-side computations.

## Key Features

-   **Privacy-Preserving Summation**: Implements a secure aggregation protocol that protects individual client data.
-   **Multi-Key Homomorphic Encryption**: Uses a custom implementation of Multi-Key CKKS, where each client has its own secret key.
-   **Additive Masking**: Employs an ECDH-based key exchange to generate pairwise secret masks that sum to zero across all clients, preventing the server from learning intermediate decrypted results.
-   **Detailed Performance Measurement**: Provides granular timing for each critical cryptographic operation on both the client and server side (e.g., key generation, encryption, mask generation, aggregation).
-   **Parallel Execution**: Leverages OpenMP to simulate clients in parallel, significantly speeding up execution on multi-core processors.
-   **Verification**: Includes a debugging utility (`debug_masking`) to verify the mathematical correctness of the mask cancellation property.

## Protocol Flow

The simulation follows a multi-round protocol to achieve secure aggregation:

1.  **Setup Phase**:
    -   A central `CryptoContext` is created using parameters suitable for the CKKS scheme.
    -   A Common Reference String (CRS), which is a publicly known polynomial, is generated and distributed.

2.  **Round 1: Key Generation**:
    -   Each client independently generates two sets of keys:
        1.  An **MK-CKKS key pair** (`sk_i`, `pk_i`) using its private secret and the public CRS.
        2.  An **ECDH key pair** for generating secure masks.
    -   The clients' public ECDH keys are distributed to all other participants.

3.  **Round 2: Client-Side Computation**:
    -   Each client `i` generates its private data vector `x_i`.
    -   For every other client `j`, client `i` uses ECDH to compute a shared secret and generates a pairwise random polynomial mask `p_ij`.
    -   The client computes its final mask `m_i` by adding and subtracting the pairwise masks based on client IDs, such that `sum(m_i)` over all clients is zero.
    -   The client adds the mask to its data (`x_i + m_i`), encrypts the result with its public key `pk_i`, and computes a partial decryption share.
    -   The client sends its encrypted, masked data and the partial decryption share to the server.

4.  **Round 3: Server-Side Aggregation**:
    -   The server receives the shares from all clients.
    -   It sums all the encrypted data components and all the partial decryption shares.
    -   Due to the properties of the MKHE scheme and the fact that the masks sum to zero, the final result is the encrypted sum of all client data vectors `Enc(sum(x_i))`.

5.  **Finalization**:
    -   The server decodes the final aggregated polynomial to retrieve the plaintext sum of the client data.
    -   The simulation verifies the correctness of the result by comparing it to the true sum, and reports any error.

## How to Build and Run

### Prerequisites

-   C++17 compatible compiler (e.g., GCC, Clang)
-   CMake (version 3.10 or higher)
-   **OpenFHE** library installed
-   **OpenSSL** library installed

### Build Instructions

The project includes a `run.sh` script that automates the build and execution process.

1.  **Make the script executable**:
    ```bash
    chmod +x run.sh
    ```
2.  **Run the script**:
    ```bash
    ./run.sh
    ```
This script will:
-   Create a clean `build` directory.
-   Run CMake to configure the project.
-   Compile the code using `make`.
-   Execute the main simulation (`secure_aggregation_sim`).

### Performance Measurement

The simulation outputs a detailed performance summary to the console and logs the results to `build/timing_log.csv`.

-   **Client-Side Timings**: The console reports the **maximum time** taken by any single client for each operation. The "Total (Worst-Case Client)" time is the sum of these maximums, representing the latency of the slowest client.
-   **Server-Side Timings**: The console reports the time taken for the server to aggregate all shares and to perform the final decoding.
-   **Log File (`timing_log.csv`)**: This file provides a per-client breakdown of the time (in milliseconds) for each cryptographic operation, allowing for more detailed analysis.

## Code Structure

-   `main.cpp`: The main entry point for the simulation. It orchestrates the protocol flow, manages clients and the server, and reports final results and performance metrics.
-   `client.h` / `client.cpp`: Defines the `Client` class, which encapsulates all client-side logic, including key generation, data masking, encryption, and preparing the share for the server.
-   `server.h` / `server.cpp`: Defines the `Server` class, which handles the aggregation of client shares and the final decoding of the result.
-   `mk_ckks.h` / `mk_ckks.cpp`: The cryptographic engine for the Multi-Key CKKS scheme. It contains low-level functions for key generation, encryption, and decoding.
-   `masking.h` / `masking.cpp`: The engine for the additive masking scheme. It uses OpenSSL to perform ECDH key exchange and generate pseudo-random polynomials from a shared secret.
-   `common.h`: A shared header file that defines common data structures, type aliases, and structs used throughout the project, including the performance timing structures.
-   `CMakeLists.txt`: The build script for CMake.
-   `run.sh`: A helper script to automate the build and run process.
-   `test_debug.cpp`: A separate executable for testing the mask cancellation property in isolation.

</markdown>