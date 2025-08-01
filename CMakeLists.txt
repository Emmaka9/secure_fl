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
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL Version: ${OPENSSL_VERSION}")

# --- Build Main Executable ---
add_executable(secure_aggregation_sim
    main.cpp
    mk_ckks.cpp
    client.cpp
    server.cpp
    masking.cpp
)

# --- Build Debugging Executable (Temporarily Disabled) ---
# The following target is commented out because its source file (test_debug.cpp)
# appears to be missing a main() function, which causes a linker error.
# This allows the primary 'secure_aggregation_sim' executable to build successfully.
#
# add_executable(debug_masking
#     test_debug.cpp
#     mk_ckks.cpp
#     client.cpp
#     masking.cpp
#     # Note: server.cpp is not needed for this test
# )

# --- Manually Add Include Directories (for robustness) ---
# Apply to both executables
target_include_directories(secure_aggregation_sim PRIVATE
    "/usr/local/include/openfhe"
    "/usr/local/include/openfhe/pke"
    "/usr/local/include/openfhe/core"
    "/usr/local/include/openfhe/binfhe"
    ${OPENSSL_INCLUDE_DIR}
)
# target_include_directories(debug_masking PRIVATE
#     "/usr/local/include/openfhe"
#     "/usr/local/include/openfhe/pke"
#     "/usr/local/include/openfhe/core"
#     "/usr/local/include/openfhe/binfhe"
#     ${OPENSSL_INCLUDE_DIR}
# )


# --- Link Libraries (Classic Method) ---
message(STATUS "Linking libraries: ${OpenFHE_LIBRARIES}")
# Apply to both executables
target_link_libraries(secure_aggregation_sim PRIVATE 
    ${OpenFHE_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)
# target_link_libraries(debug_masking PRIVATE 
#     ${OpenFHE_LIBRARIES}
#     OpenSSL::SSL
#     OpenSSL::Crypto
# )

# --- Optional: Enable OpenMP for parallel execution ---
find_package(OpenMP)
if(OpenMP_FOUND)
    message(STATUS "OpenMP found, enabling parallel execution.")
    target_link_libraries(secure_aggregation_sim PRIVATE OpenMP::OpenMP_CXX)
    # target_link_libraries(debug_masking PRIVATE OpenMP::OpenMP_CXX)
else()
    message(WARNING "OpenMP not found. The simulation will run on a single core.")
endif()

message(STATUS "SUCCESS: Configuration complete.")

