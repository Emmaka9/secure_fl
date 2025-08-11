// client.h

#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

class Client {
public:
    Client(uint32_t id);

    // MODIFIED: This function will now store timings internally.
    // The reference parameter is no longer needed.
    void generateKeys(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a);

    void generateData(uint32_t dataSize, double minVal = -10.0, double maxVal = 10.0);
    ClientResult prepareShareForServer(CryptoContext<DCRTPoly>& cc, const std::map<uint32_t, ECDHPublicKey>& allPublicKeys);

    uint32_t getId() const;
    const std::vector<double>& getData() const;
    ECDHPublicKey getECDHPublicKey() const;

private:
    uint32_t m_id;
    MKeyGenKeyPair m_keys;
    SafePKey m_ecdhKeys;
    std::vector<double> m_data;

    // NEW: Add a member variable to permanently store this client's key generation timings.
    KeyGenTimings m_keyGenTimings;
};

#endif // CLIENT_H