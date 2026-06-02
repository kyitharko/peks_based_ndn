Private key α: scalar in Fr.
Rationale: As shown in the original paper, the secret material is a scalar, not a group element.


Generator g and public key h = g^α: in G₂.
Rationale: g and h stay in larger group G₂ letting g^r in G₂ because the pairing equation e(T_W, g^r) in the Test operation requires the second argument to be in the group G₂ (since e: G₁ × G₂ → G_T). Though G₂ elements are larger (~96 bytes) and slower than G₁, it is acceptable because the public key is generated once and stored long-term, not in the network devices such as routers.


Hash-to-curve H₁(W): outputs to G₁.
Rationale: This implementation focus about routers' performance throughout network. Therefore the pairing equation's first argument must be in G₁, and since T_W = H₁(W)^α must be the first argument to the pairing in Test, H₁ must output to G₁. The reason is that G₁ operations are roughly faster than G₂ on BLS12-381, and hash-to-curve is computed for every keyword on every encryption and trapdoor generation.