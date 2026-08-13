# PEKS-NDN

Rust reference implementation of the **PEKS-based Named Data Networking (NDN) name-privacy strategy** proposed by Ko et al.

Named Data Networking is a network architecture where content is requested by name rather than by host address. Because interest names travel in plaintext across the network, routers and eavesdroppers can observe which content each consumer is requesting. This project applies Public-key Encryption with Keyword Search (PEKS) to the NDN name layer so that routers can still perform name-based matching and caching, but cannot learn what content is being requested.

The implementation reimplements the original pairing-based construction using **BLS12-381 and arkworks**, and includes the NDN-side mechanisms needed to demonstrate encrypted-name forwarding, trapdoor matching, and reactive caching.

## Status

The core cryptography, NDN name layer, protocol formats, router state, and an end-to-end demonstration are implemented.

### Implemented

* PEKS operations: `KeyGen`, `Encrypt`, `Trapdoor`, and `Test`
* BLS12-381 asymmetric pairings using arkworks
* Keyword hash-to-curve with domain separation (RFC 9380 SSWU-RO style)
* Cryptographic serialization and deserialization
* NDN name parsing and per-component PEKS conversion (`NameCiphertext`, `NameTrapdoor`)
* Trapdoor table with exhaustive matching based on Algorithm 1 of the original work
* Exact-match and longest-prefix matching
* Encrypted-interest wire format
* `TwReg` prefix registration
* `Tw` reactive trapdoor updates
* PEKS Content Store
* Pending-interest tracking using SHA-256 identifiers
* End-to-end consumer → router → producer demonstration
* Unit tests for cryptographic and protocol components

### Not yet implemented

* Integration with the NDN Forwarding Daemon (NFD)
* Production FIB integration
* Bounded Content Store and eviction policies
* Multi-router topology
* Signed Interest and Data packets
* Public-key dissemination flow (paper Section 3.3)
* Sorted-table prefix-skip optimization
* Full reproduction of the original experimental evaluation
* Formal security proof for the asymmetric BLS12-381 instantiation
* Independent side-channel and constant-time audit

## Requirements

* Rust 1.75 or later
* `cargo` and standard Rust toolchain

## Build and Test

```bash
git clone https://github.com/kyitharko/peks_based_ndn.git
cd peks_based_ndn/peks_ndn
cargo test
```

The test suite covers the PEKS primitives, serialization, NDN name processing, wire formats, trapdoor matching, Content Store, and pending-interest tracker.

## Run the End-to-End Demo

```bash
cd peks_ndn
cargo run --release --example end_to_end
```

The demo simulates a small network of one producer, one router, and one consumer, using 50 registered content names and 50 randomized requests.

The output reports:

* cache hits and misses
* cache-hit ratio
* average request time
* average cache-hit time
* average cache-miss time

Use `--release` for meaningful timings; pairing operations are significantly slower in debug builds.

The protocol flow exercised by the demo is documented in [`PROTOCOL.md`](PROTOCOL.md).

## Minimal Example

```rust
use peks_ndn::generate_key_pair;
use peks_ndn::ndn::name::name_to_ciphertext;
use peks_ndn::ndn::wire::encode_ciphertext_name;

// A producer generates its keypair; the private key stays with the producer.
let (_private_key, public_key) = generate_key_pair();

// A consumer with only the producer's public key encrypts a content name.
let encrypted_name =
    name_to_ciphertext(&public_key, "/producer/alice/profile").unwrap();

// The result is a URI safe for transmission through the NDN network.
let interest_uri = encode_ciphertext_name(&encrypted_name);

println!("{interest_uri}");
```

For the complete producer / router / consumer flow, see [`peks_ndn/examples/end_to_end.rs`](peks_ndn/examples/end_to_end.rs).

## Repository Structure

```text
peks_based_ndn/
├── README.md
├── DESIGN.md
├── PROTOCOL.md
│
└── peks_ndn/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs
    │   ├── peks.rs
    │   ├── hash.rs
    │   ├── utils.rs
    │   └── ndn/
    │       ├── helper.rs
    │       ├── name.rs
    │       ├── table.rs
    │       ├── wire.rs
    │       ├── cs.rs
    │       └── pending.rs
    │
    └── examples/
        ├── end_to_end.rs
        └── names.txt
```

## Documentation

### [`DESIGN.md`](DESIGN.md)

Cryptographic design and implementation:

* migration from the original symmetric pairing to BLS12-381
* `G1` / `G2` group placement rationale
* PEKS construction and correctness derivation
* hash and serialization choices
* security assumptions and limitations
* future cryptographic work

### [`PROTOCOL.md`](PROTOCOL.md)

NDN protocol layer:

* producer, router, and consumer roles
* encrypted-interest format
* trapdoor registration and reactive updates
* cold-path and warm-path request flows
* router state
* interest-hash linkage
* remaining NFD integration work

## Security Notice

This repository is a **research and reference implementation**, not a production cryptographic library. A formal security analysis of the BLS12-381 asymmetric instantiation is future work. See [`DESIGN.md`](DESIGN.md) for a complete list of security limitations and open items.

## References

K. T. Ko, H. H. Hlaing, and M. Mambo,
**"A PEKS-Based NDN Strategy for Name Privacy,"**
*Future Internet*, vol. 12, no. 8, article 130, 2020.
DOI: [`10.3390/fi12080130`](https://doi.org/10.3390/fi12080130)

K. T. Ko and M. Mambo,
**"Trapdoor Assignment of PEKS-based NDN Strategy in Two-Tier Networks,"**
*2020 IEEE 16th International Conference on Mobility, Sensing and Networking (MSN)*,
Tokyo, Japan, pp. 607–613.
DOI: [`10.1109/MSN50589.2020.00099`](https://doi.org/10.1109/MSN50589.2020.00099)

## License

*(Pending — commonly MIT, Apache-2.0, or dual MIT/Apache-2.0 for Rust projects.)*

## Contributions

Issues and pull requests are welcome.