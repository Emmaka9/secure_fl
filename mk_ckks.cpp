// mk_ckks.cpp
//
// Implementation of the MK-CKKS cryptographic engine. This file contains the
// definitions of all the core cryptographic functions.

#include "mk_ckks.h"

/**
 * @brief Generates the Common Reference String (CRS), which is the shared polynomial 'a'.
 */
DCRTPoly GenerateCRS(CryptoContext<DCRTPoly>& cc) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    return DCRTPoly(dug, params, Format::EVALUATION);
}

/**
 * @brief Generates a single key pair for a client using the provided CRS.
 */
MKeyGenKeyPair KeyGenSingle(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    auto cryptoParams = std::dynamic_pointer_cast<const CryptoParametersRNS>(cc->GetCryptoParameters());
    auto& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    DCRTPoly s_i(dgg, params, Format::EVALUATION);
    DCRTPoly e_i(dgg, params, Format::EVALUATION);
    DCRTPoly b_i = s_i.Negate() * crs_a + e_i;
    
    MKeyGenKeyPair kp;
    kp.sk.s = s_i;
    kp.pk.b = b_i;
    kp.pk.a = crs_a;
    
    return kp;
}

/**
 * @brief Encodes a vector of doubles into a DCRTPoly using the official library encoder.
 */
DCRTPoly encodeVector(CryptoContext<DCRTPoly>& cc, const std::vector<double>& vec) {
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(vec);
    return ptxt->GetElement<DCRTPoly>();
}

/**
 * @brief Encrypts a plaintext polynomial.
 */
MKCiphertext Encrypt(CryptoContext<DCRTPoly>& cc, const MKeyGenPublicKey& pk, const DCRTPoly& m) {
    auto cryptoParams = std::dynamic_pointer_cast<const CryptoParametersRNS>(cc->GetCryptoParameters());
    auto params = cc->GetCryptoParameters()->GetElementParams();
    auto& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    DCRTPoly v(dgg, params, Format::EVALUATION);
    DCRTPoly e0(dgg, params, Format::EVALUATION);
    DCRTPoly e1(dgg, params, Format::EVALUATION);

    DCRTPoly m_ntt = m;
    if (m_ntt.GetFormat() == Format::COEFFICIENT) {
        m_ntt.SwitchFormat();
    }

    MKCiphertext ct;
    ct.c0 = v * pk.b + m_ntt + e0;
    ct.c1 = v * pk.a + e1;

    return ct;
}

/**
 * @brief Computes a client's partial decryption polynomial 'd'.
 */
DCRTPoly ComputePartialDecryption(CryptoContext<DCRTPoly>& cc, const MKeyGenSecretKey& sk, const MKCiphertext& ct) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    
    DiscreteGaussianGeneratorImpl<NativeVector> dgg_large_variance(4.0);
    DCRTPoly e_star(dgg_large_variance, params, Format::EVALUATION);

    // Return just the polynomial d = c1*s + e*
    return ct.c1 * sk.s + e_star;
}


/**
 * @brief Decodes a raw DCRTPoly back into a vector of doubles using the OpenFHE API.
 */
std::vector<double> Decode(const DCRTPoly& finalPoly, CryptoContext<DCRTPoly>& cc, uint32_t dataSize) {
    // 1. Generate a temporary, standard keypair to create valid crypto objects.
    KeyPair<DCRTPoly> tempKeys = cc->KeyGen();

    // 2. Encrypt a dummy value to get a fully-formed, valid Ciphertext object.
    std::vector<double> dummy_vec = {0.0};
    Plaintext ptxt_template = cc->MakeCKKSPackedPlaintext(dummy_vec);
    Ciphertext<DCRTPoly> dummyCiphertext = cc->Encrypt(tempKeys.publicKey, ptxt_template);

    // 3. Overwrite the contents of this valid ciphertext with our data.
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly c1_zero(params, Format::EVALUATION, true); // true initializes to zero
    dummyCiphertext->SetElements({finalPoly, c1_zero});

    // 4. Call the standard Decrypt function. It computes `c0 + c1*s`, which is just `c0`
    // since `c1` is zero. It then handles the wrapping and decoding.
    Plaintext resultPlaintext;
    cc->Decrypt(tempKeys.secretKey, dummyCiphertext, &resultPlaintext);

    // 5. Extract and return the final vector of doubles.
    resultPlaintext->SetLength(dataSize);
    return resultPlaintext->GetRealPackedValue();
}
