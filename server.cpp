// server.cpp
//
// Implementation of the Server class.

#include "server.h"
#include "mk_ckks.h" // Include the crypto engine

Server::Server() {}

void Server::collectShare(const ClientShare& share) {
    m_clientShares.push_back(share);
}

DCRTPoly Server::aggregateShares() {
    if (m_clientShares.empty()) {
        throw std::runtime_error("No client shares to aggregate.");
    }

    DCRTPoly result = m_clientShares[0].c0;
    for (size_t i = 1; i < m_clientShares.size(); ++i) {
        result += m_clientShares[i].c0;
    }
    // The server sums the MASKED shares. The masks will cancel out.
    DCRTPoly result1 = m_clientShares[0].d_masked;
    for (const auto& share : m_clientShares) {
        result1 += share.d_masked;
    }
    std::cout << "Server: result1: " << result1 << std::endl;
    return result + result1;
}

std::vector<double> Server::getFinalResult(CryptoContext<DCRTPoly>& cc, uint32_t dataSize) {
    // 1. Aggregate all the collected shares into a single raw polynomial.
    DCRTPoly finalPoly = aggregateShares();
    std::cout << "Server has aggregated all shares." << std::endl;

    // 2. Call the crypto engine to decode the raw polynomial into a vector of doubles.
    std::vector<double> finalResult = Decode(finalPoly, cc, dataSize);
    std::cout << "Server has decoded the final result." << std::endl;
    
    return finalResult;
}
