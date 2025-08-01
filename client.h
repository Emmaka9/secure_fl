// client.h
//
// Header file for the Client class.

#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

class Client {
public:
    // MODIFIED: Constructor is now simpler.
    Client(uint32_t id);

    // NEW: Separated key generation function to allow for granular timing.
    void generateKeys(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a, KeyGenTimings& timings);

    // Generates random data to simulate a model update.
    void generateData(uint32_t dataSize, double minVal = -10.0, double maxVal = 10.0);

    // Orchestrates the client-side crypto protocol, now including masking.
    // It returns a ClientResult struct containing both the share and the timings.
    ClientResult prepareShareForServer(CryptoContext<DCRTPoly>& cc, const std::map<uint32_t, ECDHPublicKey>& allPublicKeys);

    // Getters for public information
    uint32_t getId() const;
    const std::vector<double>& getData() const;
    ECDHPublicKey getECDHPublicKey() const;

private:
    uint32_t m_id;
    MKeyGenKeyPair m_keys;
    SafePKey m_ecdhKeys; // Client now holds its own ECDH keys
    std::vector<double> m_data;
};

#endif // CLIENT_H
