Private key α: scalar in Fr (not a group element)
Generator g and public key h = g^α: in G₂ (larger, slower group — but computed once, stored, rarely changed)
Hash-to-curve H₁(W): outputs to G₁ (smaller, faster group)
Trapdoor T_W = H₁(W)^α: in G₁ (smaller — good because trapdoors are transmitted often)
Ciphertext first component g^r: in G₂ (must be in same group as g)
Ciphertext second component H₂(t): a hash output, not a group element