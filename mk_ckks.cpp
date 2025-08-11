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
 * @brief MODIFIED: Encrypts a plaintext and immediately computes the partial decryption share.
 * This function now correctly takes the secret key `sk` as an argument to perform its calculation.
 * @param cc The crypto context.
 * @param pk The public key of the client.
 * @param sk The secret key of the client.
 * @param m The plaintext polynomial to encrypt.
 * @return An MKCiphertext struct where c1 is the partial decryption share 'd'.
 */
MKCiphertext Encrypt(CryptoContext<DCRTPoly>& cc, 
                    const MKeyGenPublicKey& pk, 
                    const MKeyGenSecretKey& sk, // sk is now available
                    const DCRTPoly& m) {
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
    // Compute c0 as usual
    ct.c0 = v * pk.b + m_ntt + e0;
    
    // Compute the intermediate c1
    DCRTPoly intermediate_c1 = v * pk.a + e1;

    // Define the large decryption noise
    DiscreteGaussianGeneratorImpl<NativeVector> dgg_large_variance(4.0);
    DCRTPoly e_star(dgg_large_variance, params, Format::EVALUATION);

    // Compute the final second component, which is the partial decryption share d.
    // This now works because `sk` is passed into the function.
    ct.c1 = intermediate_c1 * sk.s + e_star;

    return ct;
}

/**
 * @brief Decodes a raw DCRTPoly back into a vector of doubles using the OpenFHE API.
 */
std::vector<double> Decode(const DCRTPoly& finalPoly, CryptoContext<DCRTPoly>& cc, uint32_t dataSize) {
    KeyPair<DCRTPoly> tempKeys = cc->KeyGen();
    std::vector<double> dummy_vec = {0.0};
    Plaintext ptxt_template = cc->MakeCKKSPackedPlaintext(dummy_vec);
    Ciphertext<DCRTPoly> dummyCiphertext = cc->Encrypt(tempKeys.publicKey, ptxt_template);
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly c1_zero(params, Format::EVALUATION, true);
    dummyCiphertext->SetElements({finalPoly, c1_zero});
    Plaintext resultPlaintext;
    cc->Decrypt(tempKeys.secretKey, dummyCiphertext, &resultPlaintext);
    resultPlaintext->SetLength(dataSize);
    return resultPlaintext->GetRealPackedValue();
}
