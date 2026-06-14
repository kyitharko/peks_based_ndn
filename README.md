# peks_ndn

Rust reimplementation of the PEKS-based NDN strategy from Ko et al. (2020). Uses BLS12-381 via arkworks for the asymmetric pairing.

## Status

Work in progress. Implements the full PEKS scheme:

- Keypair generation (G₂ public key, scalar private key)
- Hash-to-curve for keywords to G₁ (IETF RFC 9380, SSWU map)
- Encryption (probabilistic; same keyword encrypts to different ciphertexts)
- Trapdoor generation (deterministic, key-bound)
- Test operation (matching ciphertexts against trapdoors)

Test suite covers determinism of hash-to-curve and trapdoors, probabilistic behavior of encryption, key-binding of trapdoors, and end-to-end round-trip correctness.

See `DESIGN.md` for the cryptographic design rationale.

## Build and test
cd peks_ndn
cargo test
## Example

```rust
use peks_ndn::{generate_key_pair, encrypt, generate_trapdoor, test};

// Producer generates a keypair
let (private_key, public_key) = generate_key_pair();

// Producer encrypts a keyword (probabilistic — different output each call)
let ciphertext = encrypt(&public_key, b"alice").unwrap();

// Producer issues a trapdoor for the same keyword
let trapdoor = generate_trapdoor(&private_key, b"alice").unwrap();

// Router checks whether the ciphertext matches the trapdoor's keyword
assert!(test(&trapdoor, &ciphertext));
```

## Repository structure

```
peks_ndn/
├── src/
│   ├── lib.rs      Gateway: type definitions and module declarations
│   ├── peks.rs     Core PEKS operations (KeyGen, Encrypt, Trapdoor, Test)
│   ├── hash.rs     Hash-to-curve primitive
│   └── utils.rs    Shared helpers (random sampling, pairing serialization)
└── Cargo.toml
```

## Citation

K. T. Ko, H. H. Hlaing, M. Mambo, "A PEKS-Based NDN Strategy for Name Privacy," Future Internet 12(8), 130 (2020). https://doi.org/10.3390/fi12080130