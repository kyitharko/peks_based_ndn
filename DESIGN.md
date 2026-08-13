# Cryptographic Design Rationale

## Summary

This document describes the cryptographic design of the Rust PEKS-NDN
reference implementation. The construction is standard Boneh PEKS adapted
from the original symmetric pairing (PBC Type A) to BLS12-381 asymmetric
pairing (arkworks). Trapdoors are placed in `G1` and public-key / ciphertext
values in `G2` to minimize router-side storage. Hash-to-curve follows
RFC 9380 (SSWU-RO) with domain separation. The digest hash is SHA-256,
reducing wire overhead compared to the original implementation. Algebraic
correctness is preserved under the chosen group placement; formal security
analysis for the asymmetric setting is future work.

## Audience and Scope

This document is written for readers familiar with pairing-based
cryptography and the PEKS construction. It records the design choices made
when translating the original symmetric-pairing scheme from Ko et al. (2020)
to BLS12-381.

For the protocol-level architecture, wire formats, message flows, and NDN
integration, see [`PROTOCOL.md`](PROTOCOL.md).

For background on PEKS and its application to NDN, see the two papers
referenced at the end of this document.

## Design Objective

The objective is to preserve the protocol-level PEKS behavior of the
original work while adapting the construction to a modern Rust pairing
library. Because BLS12-381 uses distinct source groups, the translation
requires explicit placement of each protocol value in either `G1` or `G2`.

The algebraic correctness of the resulting construction is implemented and
tested. However, the original security proof was developed for a symmetric
pairing setting and should not be assumed to transfer unchanged to this
asymmetric instantiation.

## Notation

| Symbol       | Meaning                                                  |
| ------------ | -------------------------------------------------------- |
| `α`          | Producer's private scalar                                |
| `g`          | Fixed generator of `G2`                                  |
| `h`          | Producer's public key, `h = αg`                          |
| `r`          | Fresh random scalar sampled per encryption               |
| `W`          | Plaintext keyword (a single NDN name component)          |
| `H1`         | Hash-to-curve map from bytes to `G1`                     |
| `H2`         | SHA-256 applied to the serialization of a `GT` element   |
| `T_W`        | Trapdoor for `W`, `T_W = αH1(W)`                         |
| `(A, B)`     | PEKS ciphertext components                               |
| `e`          | Bilinear pairing `e : G1 × G2 → GT`                      |

Additive notation is used throughout for group operations.

## Pairing Setting

BLS12-381 provides an asymmetric bilinear pairing:

```text
e : G1 × G2 → GT
```

where `G1` and `G2` are distinct source groups.

This differs from the symmetric pairing used by the original PBC Type A
implementation, where both inputs to the pairing belonged to the same
source group.

The Rust implementation assigns the PEKS values as follows:

| Value          | Group / Type   | Purpose                     |
| -------------- | -------------- | --------------------------- |
| `α`            | `Fr`           | Private key scalar          |
| `g`            | `G2`           | Generator                   |
| `h = αg`       | `G2`           | Public key                  |
| `H1(W)`        | `G1`           | Keyword mapped to curve     |
| `T_W = αH1(W)` | `G1`           | Keyword trapdoor            |
| `A = rg`       | `G2`           | First ciphertext component  |
| `B`            | 32 bytes       | Second ciphertext component |

This placement makes the PEKS `Test` operation type-correct:

```text
e(T_W, A)
```

because the first pairing argument is in `G1` and the second is in `G2`.

## Group Placement Rationale

The implementation places `H1(W)` and the resulting trapdoor `T_W` in `G1`.

This choice is motivated primarily by the intended NDN deployment.

Trapdoors are stored and repeatedly used by routers during encrypted-name
matching. On BLS12-381, compressed `G1` points are 48 bytes and compressed
`G2` points are 96 bytes. Keeping trapdoors in `G1` therefore halves
router-side trapdoor storage and the size of trapdoors transmitted in
protocol messages.

Additionally, keyword hash-to-curve operations and trapdoor scalar
multiplications operate on `G1`, which is faster than the corresponding
operations on `G2`.

The trade-off is that the first ciphertext component

```text
A = rg
```

belongs to `G2`, so each encrypted name component contains a 96-byte
compressed point rather than a 48-byte one. Combined with the 32-byte SHA-256
digest, a serialized PEKS ciphertext is 128 bytes per name component. A
serialized trapdoor is 48 bytes per name component.

Because trapdoors are stored on routers in large numbers while ciphertexts
are transmitted per-request, this placement optimizes the storage-dominant
side of the system.

This is an explicit engineering choice in the current reference
implementation rather than a claim that this group assignment is optimal
for every deployment. Alternative `G1`/`G2` placements could be benchmarked
if ciphertext wire size becomes the dominant constraint.

## PEKS Construction

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

### Encryption

To encrypt keyword `W`, sample a fresh random scalar:

```text
r ∈ Fr
```

Compute:

```text
A = rg
```

The implementation then computes:

```text
Z = e(H1(W), rh)
```

by first computing `rh` as a `G2` scalar multiplication and then evaluating
the pairing. This is algebraically equivalent to `e(H1(W), h)^r` by
bilinearity, but the chosen ordering avoids performing an exponentiation in
`GT`, which is slower than a `G2` scalar multiplication.

The digest:

```text
B = H2(serialize(Z))
```

is then computed.

The resulting PEKS ciphertext is:

```text
C = (A, B)
```

where:

```text
A ∈ G2
B ∈ {0,1}^256
```

### Trapdoor Generation

For keyword `W`, compute:

```text
T_W = αH1(W)
```

where:

```text
T_W ∈ G1
```

For a fixed private key and keyword, the resulting trapdoor is deterministic.

### Test Operation

Given a trapdoor `T_W` and ciphertext `C = (A, B)`, compute:

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
    = e(αH1(W), rg)
    = e(H1(W), g)^(αr)
```

by bilinearity.

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
H2(serialize(e(T_W, A))) = B
```

for the matching keyword.

## Hash Functions

### H1: Keyword to G1

`H1` maps an arbitrary keyword to a point in `G1`.

The implementation uses arkworks' BLS12-381 hash-to-curve machinery with
SHA-256 and a domain separation tag following the RFC 9380 convention.

**[VERIFY]** The exact DST string used by the implementation is:

```text
PEKS-NDN_BLS12381G1_XMD:SHA-256_SSWU_RO_
```

This should be confirmed against `src/hash.rs` before publication of this
document. Any mismatch between the documented DST and the DST used in the
code will produce different curve points and break interoperability with an
independent implementation working from this specification.

Domain separation ensures that points generated for this PEKS-NDN protocol
are logically separated from points generated by another protocol that may
use the same underlying hash-to-curve construction.

Before interoperability with an independently implemented system is claimed,
the exact mapping configuration and serialized outputs should be verified
using shared test vectors.

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

**[VERIFY]** The original PEKS-NDN implementation is understood to have
used SHA-512 for this step. This should be confirmed against the original
C++/PBC codebase; if the original used a different hash function, this
document should be updated accordingly.

The Rust implementation uses SHA-256, reducing the second ciphertext
component from 64 bytes to 32 bytes and therefore reducing encrypted-interest
wire overhead by 32 bytes per name component.

This change is treated as an implementation decision. Its relationship to
the formal security parameters of the complete asymmetric PEKS construction
should be considered as part of a future formal security analysis.

## Probabilistic Encryption

PEKS encryption samples a new random scalar `r` for every encryption.

Therefore, encrypting the same keyword twice produces different ciphertexts:

```text
Encrypt(pk, "alice") → C1
Encrypt(pk, "alice") → C2

C1 != C2
```

This property is important for name privacy in NDN.

If encrypted interests were deterministic, an observer could recognize
repeated requests for the same content name even without knowing the
plaintext.

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

This deterministic property is required because routers store trapdoors and
reuse them when testing future encrypted interests.

The test suite verifies:

* probabilistic encryption;
* deterministic trapdoor generation;
* different trapdoors for different keywords;
* different trapdoors under different private keys;
* successful PEKS `Test` for matching keywords;
* failed PEKS `Test` for non-matching keywords.

## Serialization

Cryptographic values must be converted to bytes before they can be
transmitted through the NDN protocol.

The implementation uses arkworks canonical compressed serialization for
`G1` and `G2` points used as PEKS protocol values.

On BLS12-381:

* compressed `G1` point: 48 bytes
* compressed `G2` point: 96 bytes
* SHA-256 digest: 32 bytes

Therefore:

```text
Trapdoor           = 48 bytes
Ciphertext (A, B)  = 96 + 32 = 128 bytes
```

For example:

```text
Trapdoor
    ↓
compressed G1 serialization
    ↓
48 bytes
```

and:

```text
Ciphertext A
    ↓
compressed G2 serialization
    ↓
96 bytes
```

The ciphertext serialization concatenates:

```text
compressed G2 point || SHA-256 digest
```

producing 128 bytes total.

The NDN wire layer subsequently converts the binary representation into a
URI-safe encoding suitable for inclusion in NDN names. The complete
protocol-level representation is documented in [`PROTOCOL.md`](PROTOCOL.md).

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

This preserves the hierarchical structure needed for NDN prefix matching
while hiding the plaintext name components. The wire encoding of these
components is described in [`PROTOCOL.md`](PROTOCOL.md).

Routers compare encrypted name components against stored trapdoors using
the PEKS `Test` operation.

The current implementation follows the exhaustive matching strategy
described in Algorithm 1 of the original work. Optimization directions such
as sorted-table prefix-skip matching are noted as future work in
[`PROTOCOL.md`](PROTOCOL.md).

## Security Scope

This repository is a research and reference implementation.

It should not currently be treated as a production cryptographic library.

The original PEKS construction and its security analysis were expressed
using a symmetric pairing.

This implementation instead uses:

```text
e : G1 × G2 → GT
```

with BLS12-381.

Although the algebraic correctness relation carries over under the selected
group placement, the exact security reduction and hardness assumptions for
the asymmetric construction require separate analysis.

In particular, assumptions expressed in the original symmetric setting
cannot automatically be replaced with assumptions in the asymmetric setting
without proof.

Therefore, this repository does **not** claim that the original PEKS
security proof transfers unchanged to the current BLS12-381 implementation.

The formal analysis of the asymmetric construction is considered follow-on
research.

## Current Security Limitations

Several issues should be addressed before considering production deployment.

### Formal Security Proof

A rigorous security reduction for the asymmetric pairing construction is
still required.

The proof should explicitly state the hardness assumptions required in the
`G1 × G2 → GT` setting.

### Random Scalar Validation

The primary concern is that the ephemeral scalar `r` sampled during
encryption must be nonzero. A zero value would produce `A = O` (the group
identity), giving a trivially recognizable ciphertext. The private scalar
`α` must likewise be nonzero.

Arkworks' `Fr::rand` returns uniformly random field elements including zero
with negligible but nonzero probability. Explicit rejection of zero should
be added at both the private key generation and encryption sampling paths.

### Constant-Time Behavior

Operations involving private key material should be reviewed for:

* timing leakage;
* cache-based side channels;
* branch-dependent behavior;
* memory-access patterns.

The current implementation relies primarily on the security properties
provided by arkworks and has not undergone an independent side-channel
audit.

### Error Handling

Some serialization paths currently use:

```rust
unwrap()
```

because the repository was initially developed as a research reference
implementation.

Production-quality code should propagate relevant errors explicitly instead
of assuming serialization cannot fail.

### Interoperability Testing

The repository should eventually contain fixed test vectors covering:

* hash-to-curve output;
* key generation;
* trapdoor serialization;
* ciphertext serialization;
* PEKS `Test` operation.

These would allow independent implementations to confirm protocol
compatibility.

## Future Cryptographic Work

The main cryptographic follow-up tasks are:

* provide a formal security proof for the asymmetric pairing instantiation;
* identify and document the precise hardness assumptions required;
* review random scalar generation and explicitly reject invalid values
  where necessary;
* perform constant-time and side-channel analysis;
* improve error handling in cryptographic serialization paths;
* add deterministic interoperability test vectors;
* benchmark alternative `G1`/`G2` placements;
* investigate the trade-off between ciphertext size, trapdoor size, and
  router computation;
* reproduce the performance experiments from the original PEKS-NDN
  implementation.

Protocol-level work such as NFD integration, FIB integration, cache
eviction, packet signatures, public-key dissemination, and multi-router
experiments is documented separately in [`PROTOCOL.md`](PROTOCOL.md).

## References

K. T. Ko, H. H. Hlaing, and M. Mambo,
**"A PEKS-Based NDN Strategy for Name Privacy,"**
*Future Internet*, vol. 12, no. 8, 130, 2020.
DOI: `10.3390/fi12080130`

K. T. Ko and M. Mambo,
**"Trapdoor Assignment of PEKS-based NDN Strategy in Two-Tier Networks,"**
*2020 IEEE 16th International Conference on Mobility, Sensing and Networking (MSN)*,
Tokyo, Japan, pp. 607–613.
DOI: `10.1109/MSN50589.2020.00099`