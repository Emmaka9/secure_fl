// server.h
//
// Header file for the Server class.

#ifndef SERVER_H
#define SERVER_H

#include "common.h"

class Server {
public:
    Server();

    // Collects a share from a client.
    void collectShare(const ClientShare& share);

    // MODIFIED: Orchestrates the aggregation and final decoding.
    // Returns a ServerResult struct containing the final vector and timings.
    ServerResult getFinalResult(CryptoContext<DCRTPoly>& cc, uint32_t dataSize);

private:
    // Internal helper to perform the aggregation.
    DCRTPoly aggregateShares();

    std::vector<ClientShare> m_clientShares;
};

#endif // SERVER_H
