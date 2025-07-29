# CMake minimum version requirement
cmake_minimum_required(VERSION 3.10)

# Project Name
project(SecureAggregationSimulator)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Find OpenFHE Package (Classic Method) ---
find_package(OpenFHE CONFIG REQUIRED)
message(STATUS "Found OpenFHE Version: ${OpenFHE_VERSION}")

# --- Find OpenSSL Package ---
# This is required for ECDH and ChaCha20. Now that libssl-dev is installed,
# this standard command should work correctly.
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL Version: ${OPENSSL_VERSION}")

# --- Build Executable ---
# Add all your source files, including the new masking module
add_executable(secure_aggregation_sim
    main.cpp
    mk_ckks.cpp
    client.cpp
    server.cpp
    masking.cpp
)

# --- Manually Add Include Directories (for robustness) ---
# Explicitly list all required OpenFHE subdirectories.
target_include_directories(secure_aggregation_sim PRIVATE
    "/usr/local/include/openfhe"
    "/usr/local/include/openfhe/pke"
    "/usr/local/include/openfhe/core"
    "/usr/local/include/openfhe/binfhe"
    # The line below is often not needed if find_package works correctly,
    # but we include it for maximum compatibility.
    ${OPENSSL_INCLUDE_DIR}
)

# --- Link Libraries ---
# Link against both OpenFHE (using the classic variable) and 
# OpenSSL (using the modern targets provided by find_package).
message(STATUS "Linking OpenFHE libraries: ${OpenFHE_LIBRARIES}")
target_link_libraries(secure_aggregation_sim PRIVATE 
    ${OpenFHE_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# --- Optional: Enable OpenMP for parallel execution ---
find_package(OpenMP)
if(OpenMP_FOUND)
    message(STATUS "OpenMP found, enabling parallel execution.")
    target_link_libraries(secure_aggregation_sim PRIVATE OpenMP::OpenMP_CXX)
else()
    message(WARNING "OpenMP not found. The simulation will run on a single core.")
endif()

message(STATUS "SUCCESS: Configuration complete.")
