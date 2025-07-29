#!/bin/bash

# Stop the script if any command fails
set -e

# --- Configuration ---
# The directory where the project will be built
BUILD_DIR="build"

# --- Script ---
echo "🚀 Starting OpenFHE Secure Aggregation Build..."

# 1. Create a clean build directory
echo "1. Cleaning and creating build directory: ./${BUILD_DIR}"
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# 2. Configure the project with CMake
echo "2. Running CMake to configure the project..."
cd ${BUILD_DIR}
# Note: Add -DCMAKE_BUILD_TYPE=Release for performance-optimized builds
cmake ..

# 3. Build the project with Make
echo "3. Compiling the code with 'make'..."
# Use -j to build in parallel, e.g., 'make -j8'
make

# 4. Run the executable
echo "4. Running the secure aggregation simulation..."
echo "--- Program Output ---"
# Run the main simulation executable. The debug tool is for specific tests.
./secure_aggregation_sim
#./debug_masking
echo "----------------------"

echo "🎉 Build and run successful!"