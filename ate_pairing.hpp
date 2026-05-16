#pragma once
#include <mcl/bls12_381.hpp>
#include <vector>
#include <string>

class AtePairing {
public:
    using G1  = mcl::bn::G1;
    using G2  = mcl::bn::G2;
    using GT  = mcl::bn::Fp12;
    using Fr  = mcl::bn::Fr;
    using Fp6 = mcl::bn::Fp6;

    // Initializes BLS12-381. Call once per process.
    explicit AtePairing(const mcl::CurveParam& curve = mcl::BLS12_381);

    // e(P, Q) -> GT
    GT pairing(const G1& P, const G2& Q) const;

    // Two-phase: millerLoop then finalExp
    GT millerLoop(const G1& P, const G2& Q) const;
    GT finalExp(const GT& f) const;

    // Precompute G2 coefficients for repeated pairings against the same Q
    std::vector<Fp6> precomputeG2(const G2& Q) const;
    GT precomputedPairing(const G1& P, const std::vector<Fp6>& Qcoeff) const;

    // Hash a message to a curve point
    G1 hashToG1(const std::string& msg) const;
    G2 hashToG2(const std::string& msg) const;

    // Scalar operations
    static G1 mul(const G1& P, const Fr& s);
    static G2 mul(const G2& Q, const Fr& s);
    static GT pow(const GT& e, const Fr& s);
    static Fr randomScalar();
};
