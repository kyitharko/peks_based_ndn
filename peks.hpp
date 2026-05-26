#pragma once
#include "ate_pairing.hpp"
#include <string>
#include <vector>
#include <utility>

/**
 * @file peks.hpp
 * @brief Public Key Encryption with Keyword Search (PEKS) on BLS12-381.
 */

/**
 * @class PEKS
 * @brief PEKS scheme adapted from Boneh et al. (EUROCRYPT 2004) for the
 *        asymmetric Ate pairing on BLS12-381.
 *
 * The scheme lets a data owner encrypt keywords under a public key so that
 * a server holding a trapdoor for a specific keyword can test for a match
 * without learning anything else about the ciphertext.
 *
 * ### Algorithms
 *
 * | Algorithm | Formula |
 * |-----------|---------|
 * | KeyGen    | @f$\alpha \leftarrow \mathbb{Z}_p;\; pk = \alpha Q \in G_2;\; sk = \alpha@f$ |
 * | Encrypt   | @f$r \leftarrow \mathbb{Z}_p;\; A = rQ;\; B = H_2(e(H_1(W),\, r \cdot pk))@f$ |
 * | Trapdoor  | @f$T_W = \alpha \cdot H_1(W) \in G_1@f$ |
 * | Test      | @f$H_2(e(T_W, A)) \stackrel{?}{=} B@f$ |
 *
 * **Correctness:**
 * @f[
 *   e(\alpha H_1(W),\, rQ) = e(H_1(W), Q)^{\alpha r} = e(H_1(W),\, r\alpha Q)
 * @f]
 *
 * ### Hash functions
 * - **H₁**: hash-to-G1 via mcl's Shallue–van de Woestijne encoding.
 * - **H₂**: SHA-512 of the canonical 576-byte serialisation of the Fp12 element,
 *           producing a 64-byte digest.
 *
 * ### Security
 * IND-CKA secure in the random oracle model under the BDH assumption on BLS12-381.
 *
 * ### Usage
 * @code
 * AtePairing bp;
 * PEKS peks(bp);
 *
 * auto [pk, sk] = peks.keygen();
 *
 * PEKS::Ciphertext c  = peks.encrypt(pk, "alice");
 * PEKS::Trapdoor   td = peks.trapdoor(sk, "alice");
 *
 * assert(peks.test(c, td));           // true
 * assert(!peks.test(c, peks.trapdoor(sk, "bob")));  // false
 * @endcode
 *
 * @see AtePairing for the underlying pairing primitives.
 * @see PeksName for wire-encoding PEKS types as NDN Name components.
 */
class PEKS {
public:
    /** @brief Public key: @f$pk = \alpha Q \in G_2@f$. */
    struct PublicKey  { AtePairing::G2 pk; };

    /** @brief Secret key: the scalar @f$\alpha \in \mathbb{Z}_p@f$. */
    struct SecretKey  { AtePairing::Fr alpha; };

    /**
     * @brief PEKS ciphertext for a single keyword.
     *
     * Wire layout (BLS12-381):
     * - `A`: 96 bytes — compressed G2 point @f$rQ@f$.
     * - `B`: 64 bytes — SHA-512 digest @f$H_2(e(H_1(W), r \cdot pk))@f$.
     */
    struct Ciphertext {
        AtePairing::G2       A; ///< @f$r Q \in G_2@f$
        std::vector<uint8_t> B; ///< @f$H_2(e(H_1(W), r \cdot pk))@f$ — 64 bytes
    };

    /**
     * @brief Trapdoor for a single keyword.
     *
     * Wire layout: 48 bytes — compressed G1 point @f$T_W = \alpha H_1(W)@f$.
     */
    struct Trapdoor {
        AtePairing::G1 Tw; ///< @f$\alpha \cdot H_1(W) \in G_1@f$
    };

    /**
     * @brief Construct PEKS with a shared pairing context.
     *
     * The pairing context must outlive this PEKS instance.
     * An internal G2 generator is derived by hashing the string
     * `"PEKS_G2_gen_v1"` to G2 — this makes the generator domain-separated
     * from any application-level usage.
     *
     * @param pairing Initialised AtePairing instance.
     */
    explicit PEKS(AtePairing& pairing);

    /**
     * @brief Generate a fresh key pair.
     *
     * Samples @f$\alpha \leftarrow \mathbb{Z}_p@f$ via CSPRNG.
     *
     * @return `{pk, sk}` pair.
     */
    std::pair<PublicKey, SecretKey> keygen() const;

    /**
     * @brief Encrypt a keyword under the public key.
     *
     * Samples a fresh random @f$r@f$ for each call, so the same keyword
     * produces a different ciphertext each time (semantic security).
     *
     * @param pk      Public key from keygen().
     * @param keyword Plaintext keyword (arbitrary UTF-8 string).
     * @return Ciphertext @f$(A, B)@f$.
     */
    Ciphertext encrypt(const PublicKey& pk, const std::string& keyword) const;

    /**
     * @brief Derive a trapdoor for a keyword using the secret key.
     *
     * The trapdoor allows a router to test ciphertexts for the keyword
     * without learning anything else.
     *
     * @param sk      Secret key from keygen().
     * @param keyword Plaintext keyword.
     * @return Trapdoor @f$T_W@f$.
     */
    Trapdoor trapdoor(const SecretKey& sk, const std::string& keyword) const;

    /**
     * @brief Test whether a ciphertext was produced for the trapdoor's keyword.
     *
     * Computes one Ate pairing and compares the result to the stored hash.
     * This is the core router operation: one call per (ciphertext, trapdoor) pair.
     *
     * @param c  Ciphertext @f$(A, B)@f$.
     * @param td Trapdoor @f$T_W@f$.
     * @return `true` if the ciphertext encrypts the same keyword as the trapdoor.
     */
    bool test(const Ciphertext& c, const Trapdoor& td) const;

private:
    /** @brief H₁: hash string to G1 via SvdW encoding. */
    AtePairing::G1 H1(const std::string& w) const;

    /**
     * @brief H₂: SHA-512 of the 576-byte canonical Fp12 serialisation.
     * @return 64-byte digest.
     */
    std::vector<uint8_t> H2(const AtePairing::GT& e) const;

    AtePairing&    bp_; ///< Shared pairing context.
    AtePairing::G2 Q_;  ///< Fixed G2 generator (domain-separated).
};
