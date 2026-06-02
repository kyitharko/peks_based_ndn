# peks_ndn

Rust reimplementation of the PEKS-based NDN strategy from Ko et al. (2020).
Uses BLS12-381 via arkworks for the asymmetric pairing.

## Status

Work in progress. Currently implements:
- Keypair generation (G₂ public key, scalar private key)

See DESIGN.md for the cryptographic design rationale.

## Citation

K. T. Ko, H. H. Hlaing, M. Mambo, "A PEKS-Based NDN Strategy for Name Privacy,"
Future Internet 12(8), 130 (2020). https://doi.org/10.3390/fi12080130