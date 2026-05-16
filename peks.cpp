#include "peks.hpp"

using namespace mcl::bn;

PEKS::PEKS(AtePairing& pairing) : bp_(pairing)
{
    Q_ = pairing.hashToG2("PEKS_G2_gen_v1");
}

std::pair<PEKS::PublicKey, PEKS::SecretKey> PEKS::keygen() const
{
    SecretKey sk;
    sk.alpha = AtePairing::randomScalar();
    PublicKey pk;
    pk.pk = AtePairing::mul(Q_, sk.alpha);
    return {pk, sk};
}

PEKS::Ciphertext PEKS::encrypt(const PublicKey& pk, const std::string& keyword) const
{
    Fr r = AtePairing::randomScalar();
    Ciphertext c;
    c.A = AtePairing::mul(Q_, r);                                        // r*Q
    AtePairing::GT t = bp_.pairing(H1(keyword), AtePairing::mul(pk.pk, r)); // e(H1(W), r*pk)
    c.B = H2(t);
    return c;
}

PEKS::Trapdoor PEKS::trapdoor(const SecretKey& sk, const std::string& keyword) const
{
    Trapdoor td;
    td.Tw = AtePairing::mul(H1(keyword), sk.alpha);                      // alpha * H1(W)
    return td;
}

bool PEKS::test(const Ciphertext& c, const Trapdoor& td) const
{
    AtePairing::GT e = bp_.pairing(td.Tw, c.A);                          // e(alpha*H1(W), r*Q)
    return H2(e) == c.B;
}

AtePairing::G1 PEKS::H1(const std::string& w) const
{
    return bp_.hashToG1(w);
}

std::vector<uint8_t> PEKS::H2(const AtePairing::GT& gt) const
{
    std::string s = gt.getStr(16);
    return std::vector<uint8_t>(s.begin(), s.end());
}
