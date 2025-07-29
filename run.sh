#!/bin/bash

# Stop the script if any command fails
set -e

# --- Configuration ---
# The directory where the project will be built
BUILD_DIR="build"

# --- Script ---
echo "🚀 Starting OpenFHE Test Build..."

# 1. Create a clean build directory
echo "1. Cleaning and creating build directory: ./${BUILD_DIR}"
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# 2. Configure the project with CMake
echo "2. Running CMake to configure the project..."
cd ${BUILD_DIR}
cmake ..

# 3. Build the project with Make
echo "3. Compiling the code with 'make'..."
# You can add -j4 (or another number) to build in parallel
make

# 4. Run the executable
echo "4. Running the test executable..."
echo "--- Program Output ---"
./secure_aggregation_sim
echo "----------------------"

echo "🎉 Build and run successful!"