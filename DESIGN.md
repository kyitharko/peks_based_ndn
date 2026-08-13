# Cryptographic Design Rationale

This document records the main cryptographic design decisions in the Rust reimplementation of the PEKS-based NDN strategy from Ko et al. (2020).

The original implementation used a symmetric pairing provided by the PBC library. This implementation uses the BLS12-381 asymmetric pairing provided by arkworks.

The objective is to preserve the protocol-level PEKS behavior while adapting the construction to a modern Rust pairing library. Because BLS12-381 uses distinct source groups, the translation requires explicit placement of each protocol value in either `G1` or `G2`.

The algebraic correctness of the resulting construction is implemented and tested. However, the original security proof was developed for a symmetric pairing setting and should not be assumed to transfer unchanged to this asymmetric instantiation.

## Pairing Setting

BLS12-381 provides an asymmetric bilinear pairing:

```text
e : G1 × G2 → GT
```

where `G1` and `G2` are distinct source groups.

This differs from the symmetric pairing used by the original PBC Type A implementation, where both inputs to the pairing belonged to the same source group.

The Rust implementation assigns the PEKS values as follows:

| Value          | Group / Type   | Purpose                     |
| -------------- | -------------- | --------------------------- |
| `α`            | `Fr`           | Private key scalar          |
| `g`            | `G2`           | Generator                   |
| `h = αg`       | `G2`           | Public key                  |
| `H1(W)`        | `G1`           | Keyword mapped to curve     |
| `T_W = αH1(W)` | `G1`           | Keyword trapdoor            |
| `A = rg`       | `G2`           | First ciphertext component  |
| `B`            | 32-byte digest | Second ciphertext component |

This placement makes the PEKS test operation type-correct:

```text
e(T_W, A)
```

because the first pairing argument is in `G1` and the second is in `G2`.

## Why Keyword-Derived Values Are Placed in G1

The implementation places `H1(W)` and the resulting trapdoor `T_W` in `G1`.

This choice is motivated primarily by the intended NDN deployment.

Trapdoors are stored and repeatedly used by routers during encrypted-name matching. On BLS12-381, compressed `G1` points are smaller than compressed `G2` points. Keeping trapdoors in `G1` therefore reduces router-side storage and the size of trapdoors transmitted in protocol messages.

It also means that keyword hash-to-curve operations and trapdoor scalar multiplications operate on `G1`.

The trade-off is that the first ciphertext component

```text
A = rg
```

belongs to `G2`, so each encrypted name component contains a relatively larger group element.

This is an explicit engineering choice in the current reference implementation rather than a claim that this group assignment is optimal for every deployment. Alternative `G1`/`G2` placements could be benchmarked if ciphertext wire size becomes the dominant constraint.

## PEKS Construction

The Rust implementation uses additive notation for elliptic-curve group operations.

### Key Generation

Select a private scalar:

```text
α ∈ Fr
```

Let:

```text
g ∈ G2
```

be the generator.

Compute the public key:

```text
h = αg
```

Therefore:

```text
Private key:  α
Public key:   h ∈ G2
```

## Encryption

To encrypt keyword `W`, sample a fresh random scalar:

```text
r ∈ Fr
```

Compute:

```text
A = rg
```

and:

```text
Z = e(H1(W), rh)
```

Then calculate:

```text
B = H2(serialize(Z))
```

The resulting PEKS ciphertext is:

```text
C = (A, B)
```

where:

```text
A ∈ G2
B ∈ {0,1}^256
```

## Trapdoor Generation

For keyword `W`, compute:

```text
T_W = αH1(W)
```

where:

```text
T_W ∈ G1
```

For a fixed private key and keyword, the resulting trapdoor is deterministic.

## Test Operation

Given:

```text
T_W
```

and ciphertext:

```text
C = (A, B)
```

compute:

```text
B' = H2(serialize(e(T_W, A)))
```

The keyword matches when:

```text
B' == B
```

## Correctness

For a matching keyword:

```text
T_W = αH1(W)
```

and:

```text
A = rg
```

Therefore:

```text
e(T_W, A)
```

becomes:

```text
e(αH1(W), rg)
```

By bilinearity:

```text
e(αH1(W), rg)
    = e(H1(W), g)^(αr)
```

The encryption operation computes:

```text
e(H1(W), rh)
```

Since:

```text
h = αg
```

then:

```text
rh = rαg
```

and therefore:

```text
e(H1(W), rh)
    = e(H1(W), rαg)
    = e(H1(W), g)^(αr)
```

Hence:

```text
e(T_W, A) = e(H1(W), rh)
```

and both sides produce the same input to `H2`.

Therefore:

```text
H2(e(T_W, A)) = B
```

for the matching keyword.

## Hash Functions

### H1: Keyword to G1

`H1` maps an arbitrary keyword to a point in `G1`.

The implementation uses arkworks' BLS12-381 hash-to-curve machinery with SHA-256 and the domain separation tag:

```text
PEKS-NDN_BLS12381G1_XMD:SHA-256_SSWU_RO_
```

The intent is to follow an RFC 9380-style hash-to-curve construction with explicit domain separation.

Domain separation ensures that points generated for this PEKS-NDN protocol are logically separated from points generated by another protocol that may use the same underlying hash-to-curve construction.

Before interoperability with an independently implemented system is claimed, the exact mapping configuration and serialized outputs should be verified using shared test vectors.

### H2: Pairing Output to Bytes

`H2` hashes the serialized pairing result using SHA-256.

Conceptually:

```text
H2 : GT → {0,1}^256
```

The implementation performs:

```text
GT element
    ↓
canonical serialization
    ↓
SHA-256
    ↓
32-byte digest
```

The original PEKS-NDN implementation used SHA-512.

The Rust implementation uses SHA-256, reducing the second ciphertext component from 64 bytes to 32 bytes and therefore reducing encrypted-interest wire overhead.

This change is treated as an implementation decision. Its relationship to the formal security parameters of the complete asymmetric PEKS construction should be considered as part of a future formal security analysis.

## Probabilistic Encryption

PEKS encryption samples a new random scalar `r` for every encryption.

Therefore, encrypting the same keyword twice produces different ciphertexts:

```text
Encrypt(pk, "alice") → C1
Encrypt(pk, "alice") → C2

C1 != C2
```

This property is important for name privacy in NDN.

If encrypted interests were deterministic, an observer could recognize repeated requests for the same content name even without knowing the plaintext.

The implementation therefore maintains:

```text
Encryption: probabilistic
Trapdoor:   deterministic
```

For a fixed private key and keyword:

```text
Trapdoor(sk, W)
```

always produces the same trapdoor.

This deterministic property is required because routers store trapdoors and reuse them when testing future encrypted interests.

The test suite verifies:

* probabilistic encryption;
* deterministic trapdoor generation;
* different trapdoors for different keywords;
* different trapdoors under different private keys;
* successful PEKS tests for matching keywords;
* failed PEKS tests for non-matching keywords.

## Serialization

Cryptographic values must be converted to bytes before they can be transmitted through the NDN protocol.

The implementation uses arkworks canonical compressed serialization for `G1` and `G2` points used as PEKS protocol values.

For example:

```text
Trapdoor
    ↓
compressed G1 serialization
    ↓
bytes
```

and:

```text
Ciphertext A
    ↓
compressed G2 serialization
    ↓
bytes
```

The ciphertext serialization combines:

```text
compressed G2 point || SHA-256 digest
```

The NDN wire layer subsequently converts the binary representation into a URI-safe encoding suitable for inclusion in NDN names.

The complete protocol-level representation is documented in [`PROTOCOL.md`](PROTOCOL.md).

## NDN Design Implications

The PEKS construction operates on individual NDN name components.

For example:

```text
/producer/alice/profile
```

is conceptually divided into:

```text
producer
alice
profile
```

Each component is independently encrypted:

```text
PEKS("producer")
PEKS("alice")
PEKS("profile")
```

producing an encrypted name:

```text
C1 / C2 / C3
```

Similarly, the corresponding trapdoor representation contains:

```text
T1 / T2 / T3
```

This preserves the hierarchical structure needed for NDN prefix matching while hiding the plaintext name components.

Routers compare encrypted name components against stored trapdoors using the PEKS `Test` operation.

The current implementation follows the exhaustive matching strategy described in Algorithm 1 of the original work.

## Security Scope

This repository is a research/reference implementation.

It should not currently be treated as a production cryptographic library.

The original PEKS construction and its security analysis were expressed using a symmetric pairing.

This implementation instead uses:

```text
e : G1 × G2 → GT
```

with BLS12-381.

Although the algebraic correctness relation carries over under the selected group placement, the exact security reduction and hardness assumptions for the asymmetric construction require separate analysis.

In particular, assumptions expressed in the original symmetric setting cannot automatically be replaced with assumptions in the asymmetric setting without proof.

Therefore, this repository does **not** claim that the original PEKS security proof transfers unchanged to the current BLS12-381 implementation.

The formal analysis of the asymmetric construction is considered follow-on research.

## Current Security Limitations

Several issues should be addressed before considering production deployment.

### Formal Security Proof

A rigorous security reduction for the asymmetric pairing construction is still required.

The proof should explicitly state the hardness assumptions required in the `G1 × G2 → GT` setting.

### Random Scalar Validation

Secret and ephemeral scalars should be reviewed to ensure that invalid values such as zero are explicitly excluded where required by the construction.

The current random-generation implementation should therefore receive an additional cryptographic review.

### Constant-Time Behavior

Operations involving private key material should be reviewed for:

* timing leakage;
* cache-based side channels;
* branch-dependent behavior;
* memory-access patterns.

The current implementation relies primarily on the security properties provided by arkworks and has not undergone an independent side-channel audit.

### Error Handling

Some serialization paths currently use:

```rust
unwrap()
```

because the repository was initially developed as a research reference implementation.

Production-quality code should propagate relevant errors explicitly instead of assuming serialization cannot fail.

### Interoperability Testing

The repository should eventually contain fixed test vectors covering:

* hash-to-curve output;
* key generation;
* trapdoor serialization;
* ciphertext serialization;
* PEKS matching.

These would allow independent implementations to confirm protocol compatibility.

## Future Cryptographic Work

The main cryptographic follow-up tasks are:

* provide a formal security proof for the asymmetric pairing instantiation;
* identify and document the precise hardness assumptions required;
* review random scalar generation and explicitly reject invalid values where necessary;
* perform constant-time and side-channel analysis;
* improve error handling in cryptographic serialization paths;
* add deterministic interoperability test vectors;
* benchmark alternative `G1`/`G2` placements;
* investigate the trade-off between ciphertext size, trapdoor size, and router computation;
* reproduce the performance experiments from the original PEKS-NDN implementation.

Protocol-level work such as NFD integration, FIB integration, cache eviction, packet signatures, public-key dissemination, and multi-router experiments is documented separately in [`PROTOCOL.md`](PROTOCOL.md).

## References

K. T. Ko, H. H. Hlaing, and M. Mambo,
**“A PEKS-Based NDN Strategy for Name Privacy,”**
*Future Internet*, vol. 12, no. 8, 130, 2020.
DOI: `10.3390/fi12080130`

K. T. Ko and M. Mambo,
**“Trapdoor Assignment of PEKS-based NDN Strategy in Two-Tier Networks,”**
*2020 IEEE 16th International Conference on Mobility, Sensing and Networking (MSN)*,
Tokyo, Japan, pp. 607–613.
DOI: `10.1109/MSN50589.2020.00099`
