# peks_ndn

Rust reimplementation of the PEKS-based NDN strategy from Ko et al. (2020).
Uses BLS12-381 asymmetric pairings via arkworks.

## Status

Reference implementation. The core cryptography, NDN name layer, protocol
formats, router state, and an end-to-end demonstration are complete. Real
NFD integration and experimental reproduction of the paper's Section 5
measurements are not yet done.

**What's implemented:**

- Full Boneh PEKS scheme (KeyGen, Encrypt, Trapdoor, Test) on BLS12-381
- Hash-to-curve to G1 following IETF RFC 9380 (SSWU map)
- Canonical compressed-point serialization for network transmission
- NDN name layer: parsing, per-component PEKS conversion (NameCiphertext, NameTrapdoor)
- Trapdoor table with exhaustive matching (paper Algorithm 1)
- Wire format for three URI types: encrypted interests, TwReg prefix registration,
  Tw trapdoor updates with SHA-256 hash for interest linking
- PEKS Content Store (dummy: unbounded, no eviction)
- Pending interest tracker with SHA-256 hash mapping
- End-to-end demo showing consumer → router → producer flow with metrics

**What's NOT implemented:**

- NFD integration (would require FFI wrapper or C++ strategy plugin)
- Realistic FIB (pre-populated / assumed by the demo)
- CS eviction policies (LRU, bounded size)
- Multi-router network topology (paper Figure 10)
- Signed interest packets
- Signed data packets
- Full reproduction of paper Section 5 experiments (limited by available hardware)
- Sorted-table prefix-skip optimization (deferred extension beyond paper)
- Public key dissemination flow (paper Section 3.3) — demo initializes consumer
  with public key directly

## Build and test

```
cd peks_ndn
cargo test
```

All tests should pass. This runs unit tests for the cryptographic primitives,
name layer, wire formats, trapdoor table matching, CS, and pending tracker.

## Run the demo

```
cd peks_ndn
cargo run --release --example end_to_end
```

The demo simulates a small network:

- One producer with 50 registered content names (from `examples/names.txt`)
- One router positioned between consumer and producer
- One consumer making 50 random requests

The demo reports cache hit ratio and average request times, comparing hot-path
(cache hit) and cold-path (cache miss) performance.

Use `--release` for meaningful timings — pairing operations are slow in debug mode.

## Example

```rust
use peks_ndn::generate_key_pair;
use peks_ndn::ndn::name::{name_to_ciphertext, name_to_trapdoor};
use peks_ndn::ndn::wire::{encode_ciphertext_name, decode_ciphertext_name};

// Producer generates keys
let (private_key, public_key) = generate_key_pair();

// Consumer creates an encrypted interest for a content name
let name_ciphertext = name_to_ciphertext(&public_key, "/producer/alice/profile").unwrap();
let interest_uri = encode_ciphertext_name(&name_ciphertext);

// This URI can be sent over the network. It reveals nothing about the underlying name.
// A router with the appropriate trapdoors can match it without seeing the plaintext.
```

See `examples/end_to_end.rs` for the complete producer/router/consumer flow.

## Repository structure

```
peks_ndn/
├── src/
│   ├── lib.rs              Types and module declarations
│   ├── peks.rs             Core PEKS operations (KeyGen, Encrypt, Trapdoor, Test)
│   ├── hash.rs             Hash-to-curve primitive
│   ├── utils.rs            Shared helpers (random sampling)
│   └── ndn/
│       ├── mod.rs          Module declarations
│       ├── helper.rs       Name parsing
│       ├── name.rs         Per-name conversion (NameCiphertext, NameTrapdoor)
│       ├── tables.rs       Trapdoor table with exhaustive matching
│       ├── wire.rs         URI encoding/decoding for NDN transmission
│       ├── cs.rs           PEKS Content Store and DataPacket type
│       └── pending.rs      Pending interest tracker
├── examples/
│   ├── end_to_end.rs       Producer/Router/Consumer demonstration
│   └── names.txt           Sample content names used by the demo
├── DESIGN.md               Cryptographic design rationale
├── PROTOCOL.md             Protocol architecture and message flows
└── Cargo.toml
```

## Documentation

- `DESIGN.md` — cryptographic design decisions (curve choice, group placement,
  hash function selection).
- `PROTOCOL.md` — protocol-level architecture (URI formats, router state,
  message flows, what's implemented vs deferred).

## Citation

K. T. Ko, H. H. Hlaing, M. Mambo. "A PEKS-Based NDN Strategy for Name Privacy."
*Future Internet* 12(8), 130 (2020). https://doi.org/10.3390/fi12080130

K. T. Ko, M. Mambo. "Trapdoor Assignment of PEKS-based NDN Strategy in Two-Tier
Networks." *2020 IEEE 16th MSN*, Tokyo, pp. 607–613.
https://doi.org/10.1109/MSN50589.2020.00099
