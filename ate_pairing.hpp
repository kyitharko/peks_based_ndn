#pragma once
#include <mcl/bls12_381.hpp>
#include <vector>
#include <string>

/**
 * @file ate_pairing.hpp
 * @brief Optimal Ate pairing wrapper on BLS12-381 via the mcl library.
 */

/**
 * @class AtePairing
 * @brief Asymmetric bilinear map @f$e: G_1 \times G_2 \to G_T@f$ on BLS12-381.
 *
 * Wraps [mcl](https://github.com/herumi/mcl) to expose the pairing operations
 * required by the PEKS scheme.  BLS12-381 provides 128-bit security with the
 * following group sizes:
 *
 * | Group | Representation | Compressed size |
 * |-------|---------------|-----------------|
 * | G1    | Points on E(Fp)  | 48 bytes |
 * | G2    | Points on E(Fp²) | 96 bytes |
 * | GT    | Fp12 elements    | 576 bytes |
 * | Fr    | Scalar field ℤp  | 32 bytes |
 *
 * @note Constructing this class calls `mcl::bn::initPairing()`, which
 *       initialises a global mcl context.  Create exactly **one** instance
 *       per process and share it by reference.
 *
 * ### Bilinearity
 * For any @f$P \in G_1@f$, @f$Q \in G_2@f$, and scalars @f$a, b \in \mathbb{Z}_p@f$:
 * @f[
 *   e(aP,\, bQ) = e(P,Q)^{ab}
 * @f]
 */
class AtePairing {
public:
    using G1  = mcl::bn::G1;   ///< Point on E(Fp) — 48 bytes compressed.
    using G2  = mcl::bn::G2;   ///< Point on E(Fp²) — 96 bytes compressed.
    using GT  = mcl::bn::Fp12; ///< Target group element (Fp12) — 576 bytes.
    using Fr  = mcl::bn::Fr;   ///< Scalar field element ℤp — 32 bytes.
    using Fp6 = mcl::bn::Fp6;  ///< Precomputed G2 coefficient type.

    /**
     * @brief Initialise the BLS12-381 pairing context.
     * @param curve Curve parameters (default: BLS12-381).
     */
    explicit AtePairing(const mcl::CurveParam& curve = mcl::BLS12_381);

    /** @name Core pairing */
    ///@{

    /**
     * @brief Compute the full optimal Ate pairing @f$e(P, Q)@f$.
     * @param P Point in G1.
     * @param Q Point in G2.
     * @return @f$e(P,Q) \in G_T@f$.
     */
    GT pairing(const G1& P, const G2& Q) const;

    /**
     * @brief Compute only the Miller loop part of the pairing.
     *
     * Use together with finalExp() when you need to batch multiple Miller
     * loops before the expensive final exponentiation.
     *
     * @param P Point in G1.
     * @param Q Point in G2.
     * @return Intermediate Miller loop value (not a valid GT element yet).
     */
    GT millerLoop(const G1& P, const G2& Q) const;

    /**
     * @brief Apply the final exponentiation to a Miller loop output.
     * @param f Output of millerLoop().
     * @return @f$f^{(p^{12}-1)/r} \in G_T@f$.
     */
    GT finalExp(const GT& f) const;

    ///@}

    /** @name Precomputed pairing (repeated G2 point) */
    ///@{

    /**
     * @brief Precompute line-function coefficients for a fixed G2 point.
     *
     * When the same @p Q appears in many pairings (e.g. the public key),
     * precomputing its coefficients once and reusing them is faster than
     * calling pairing() each time.
     *
     * @param Q Fixed G2 point.
     * @return Precomputed coefficient vector for use with precomputedPairing().
     */
    std::vector<Fp6> precomputeG2(const G2& Q) const;

    /**
     * @brief Compute a pairing using precomputed G2 coefficients.
     * @param P      Point in G1.
     * @param Qcoeff Coefficients returned by precomputeG2().
     * @return @f$e(P, Q) \in G_T@f$.
     */
    GT precomputedPairing(const G1& P, const std::vector<Fp6>& Qcoeff) const;

    ///@}

    /** @name Hash-to-curve */
    ///@{

    /**
     * @brief Hash an arbitrary byte string to a G1 point.
     *
     * Uses the Shallue–van de Woestijne encoding (SvdW) as implemented by mcl.
     * Models the random oracle H₁ in the PEKS scheme.
     *
     * @param msg Input message.
     * @return Deterministic point in G1.
     */
    G1 hashToG1(const std::string& msg) const;

    /**
     * @brief Hash an arbitrary byte string to a G2 point.
     * @param msg Input message.
     * @return Deterministic point in G2.
     */
    G2 hashToG2(const std::string& msg) const;

    ///@}

    /** @name Scalar arithmetic */
    ///@{

    /** @brief Scalar multiplication in G1: @f$s \cdot P@f$. */
    static G1 mul(const G1& P, const Fr& s);

    /** @brief Scalar multiplication in G2: @f$s \cdot Q@f$. */
    static G2 mul(const G2& Q, const Fr& s);

    /** @brief Exponentiation in GT: @f$e^s@f$. */
    static GT pow(const GT& e, const Fr& s);

    /**
     * @brief Sample a uniformly random scalar from ℤp using a CSPRNG.
     * @return Cryptographically random Fr element.
     */
    static Fr randomScalar();

    ///@}
};
