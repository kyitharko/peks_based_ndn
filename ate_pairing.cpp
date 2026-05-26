/**
 * @file ate_pairing.cpp
 * @brief AtePairing implementation — thin delegation to mcl primitives.
 */
#include "ate_pairing.hpp"

using namespace mcl::bn;

AtePairing::AtePairing(const mcl::CurveParam& curve)
{
    initPairing(curve);
}

AtePairing::GT AtePairing::pairing(const G1& P, const G2& Q) const
{
    GT e;
    mcl::bn::pairing(e, P, Q);
    return e;
}

AtePairing::GT AtePairing::millerLoop(const G1& P, const G2& Q) const
{
    GT f;
    mcl::bn::millerLoop(f, P, Q);
    return f;
}

AtePairing::GT AtePairing::finalExp(const GT& f) const
{
    GT e;
    mcl::bn::finalExp(e, f);
    return e;
}

std::vector<AtePairing::Fp6> AtePairing::precomputeG2(const G2& Q) const
{
    std::vector<Fp6> Qcoeff;
    mcl::bn::precomputeG2(Qcoeff, Q);
    return Qcoeff;
}

AtePairing::GT AtePairing::precomputedPairing(const G1& P, const std::vector<Fp6>& Qcoeff) const
{
    GT f;
    precomputedMillerLoop(f, P, Qcoeff);
    mcl::bn::finalExp(f, f);
    return f;
}

AtePairing::G1 AtePairing::hashToG1(const std::string& msg) const
{
    G1 P;
    hashAndMapToG1(P, msg.data(), msg.size());
    return P;
}

AtePairing::G2 AtePairing::hashToG2(const std::string& msg) const
{
    G2 Q;
    hashAndMapToG2(Q, msg.data(), msg.size());
    return Q;
}

AtePairing::G1 AtePairing::mul(const G1& P, const Fr& s)
{
    G1 R;
    G1::mul(R, P, s);
    return R;
}

AtePairing::G2 AtePairing::mul(const G2& Q, const Fr& s)
{
    G2 R;
    G2::mul(R, Q, s);
    return R;
}

AtePairing::GT AtePairing::pow(const GT& e, const Fr& s)
{
    GT r;
    GT::pow(r, e, s);
    return r;
}

AtePairing::Fr AtePairing::randomScalar()
{
    Fr s;
    s.setByCSPRNG();
    return s;
}
