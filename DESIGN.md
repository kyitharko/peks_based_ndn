# Cryptographic Design Rationale

This document contains the cryptographic design decisions made in this reimplementation, especially the reasons to transition from the original symmetric-pairing scheme to an asymmetric pairing on BLS12-381.

## Curve and pairing choice

[Paragraph: why BLS12-381 instead of PBC Type A. Three layers:
motivation (security at smaller parameters, active library ecosystem),
structural decision (asymmetric translation forced new placement choices),
security caveat 
TODO: (BDH proof corresponds to co-BDH; rigorous proof is
follow-on work).]

## Construction

Private key α: scalar in Fr. Rationale: As shown in the original paper, the secret material is a scalar, not a group element.

Generator g and public key h = g^α: in G₂. Rationale: g and h stay in larger group G₂ which means h in G₂ because the pairing equation e(T_W, g^r) in the Test operation requires the second argument to be in the group G₂ (since e: G₁ × G₂ → G_T). Though G₂ elements are larger (~96 bytes) and slower than G₁, it is acceptable because the public key is generated once and stored long-term, not in the network devices such as routers.

Hash-to-curve H₁(W): outputs to G₁. Rationale: This implementation focuses on routers' performance across the network. Therefore the pairing equation's first argument must be in G₁, and since T_W = H₁(W)^α must be the first argument to the pairing in Test, H₁ must output to G₁. The reason is that G₁ operations are faster than G₂ on BLS12-381, and hash-to-curve is computed for every keyword on every encryption and trapdoor generation.

## Hash functions

H₁ (keyword → G₁) follows IETF RFC 9380 with the SSWU map for BLS12-381.
Domain separation tag: `PEKS-NDN_BLS12381G1_XMD:SHA-256_SSWU_RO_`.

H₂ (pairing output → bytes) uses SHA-256. This is different from the
original paper, which used SHA-512. SHA-256's 32-byte output halves the
size of the second ciphertext component, reducing per-packet bandwidth
in NDN deployment.

## Probabilistic encryption

Encrypt samples a fresh random scalar r on every call. The different ciphertexts will be calculated for the same plaintext but the trapdoor for the plaintext remains deterministic. This combination preserves the security
property from Section 6 of the paper while keeping the trapdoor unique.

## Open items

- NDN name component serialization (compressed point representation + URI-safe encoding).
- Formal security proof in the asymmetric pairing setting.
- Constant-time review and side-channel hardening for production deployment.