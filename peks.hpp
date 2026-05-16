#pragma once
#include "ate_pairing.hpp"
#include <string>
#include <vector>
#include <utility>

// Public Key Encryption with Keyword Search (Boneh et al. 2004)
// adapted to asymmetric pairing e: G1 x G2 -> GT on BLS12-381.
//
// KeyGen:    alpha <- Zp; pk = alpha*Q in G2; sk = alpha
// Encrypt:   r <- Zp; A = r*Q; B = H2(e(H1(W), r*pk)); out (A,B)
// Trapdoor:  Tw = alpha * H1(W) in G1
// Test:      H2(e(Tw, A)) == B
class PEKS {
public:
    struct PublicKey  { AtePairing::G2 pk; };               // alpha * Q
    struct SecretKey  { AtePairing::Fr alpha; };
    struct Ciphertext { AtePairing::G2 A;                   // r * Q
                        std::vector<uint8_t> B; };          // H2(e(H1(W), r*pk))
    struct Trapdoor   { AtePairing::G1 Tw; };               // alpha * H1(W)

    explicit PEKS(AtePairing& pairing);

    std::pair<PublicKey, SecretKey> keygen() const;
    Ciphertext encrypt(const PublicKey& pk, const std::string& keyword) const;
    Trapdoor   trapdoor(const SecretKey& sk, const std::string& keyword) const;
    bool       test(const Ciphertext& c, const Trapdoor& td) const;

private:
    AtePairing&    bp_;
    AtePairing::G2 Q_;          // fixed G2 generator

    AtePairing::G1       H1(const std::string& w) const;
    std::vector<uint8_t> H2(const AtePairing::GT& e) const;
};
