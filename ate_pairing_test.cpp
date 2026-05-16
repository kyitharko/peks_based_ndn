#include "ate_pairing.hpp"
#include <cstdio>

int main()
{
    AtePairing bp;

    AtePairing::G1 P = bp.hashToG1("generator");
    AtePairing::G2 Q = bp.hashToG2("generator");

    printf("=== Ate Pairing on BLS12-381 ===\n\n");

    // Bilinearity
    {
        AtePairing::Fr a = AtePairing::randomScalar();
        AtePairing::Fr b = AtePairing::randomScalar();

        AtePairing::G1 aP = AtePairing::mul(P, a);
        AtePairing::G1 bP = AtePairing::mul(P, b);
        AtePairing::G2 aQ = AtePairing::mul(Q, a);
        AtePairing::G2 bQ = AtePairing::mul(Q, b);

        AtePairing::GT e   = bp.pairing(P,  Q);
        AtePairing::GT ea  = AtePairing::pow(e, a);
        AtePairing::GT eab = AtePairing::pow(e, a * b);

        printf("-- Bilinearity --\n");
        printf("e(aP, Q) == e(P,Q)^a : %s\n", bp.pairing(aP, Q)  == ea  ? "OK" : "FAIL");
        printf("e(P, aQ) == e(P,Q)^a : %s\n", bp.pairing(P,  aQ) == ea  ? "OK" : "FAIL");
        printf("e(aP, Q) == e(P, aQ) : %s\n", bp.pairing(aP, Q)  == bp.pairing(P, aQ) ? "OK" : "FAIL");
        printf("e(bP,aQ) == e(P,Q)^ab: %s\n", bp.pairing(bP, aQ) == eab ? "OK" : "FAIL");
        printf("e(aP,bQ) == e(P,Q)^ab: %s\n", bp.pairing(aP, bQ) == eab ? "OK" : "FAIL");
    }

    // Miller loop + final exponentiation
    {
        printf("\n-- Miller loop + Final exponentiation --\n");
        AtePairing::GT e1 = bp.pairing(P, Q);
        AtePairing::GT e2 = bp.finalExp(bp.millerLoop(P, Q));
        printf("millerLoop+finalExp == pairing: %s\n", e1 == e2 ? "OK" : "FAIL");
    }

    // Precomputed G2
    {
        printf("\n-- Precomputed G2 --\n");
        auto Qcoeff = bp.precomputeG2(Q);
        AtePairing::GT e1 = bp.pairing(P, Q);
        AtePairing::GT e2 = bp.precomputedPairing(P, Qcoeff);
        printf("precomputed pairing == pairing: %s\n", e1 == e2 ? "OK" : "FAIL");
    }

    // Tripartite Diffie-Hellman
    {
        printf("\n-- Tripartite Diffie-Hellman --\n");
        AtePairing::Fr a = AtePairing::randomScalar();
        AtePairing::Fr b = AtePairing::randomScalar();
        AtePairing::GT alice = bp.pairing(AtePairing::mul(P, a), AtePairing::mul(Q, b));
        AtePairing::GT bob   = AtePairing::pow(bp.pairing(P, Q), a * b);
        printf("e(aP, bQ) == e(P,Q)^ab: %s\n", alice == bob ? "OK" : "FAIL");
    }

    return 0;
}
