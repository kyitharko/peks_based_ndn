# PEKS-Based NDN — Ate Pairing Reconstruction

> **This repository is an independent C++ reconstruction authored by Ko, Kyi Thar,
> one of the original authors of the paper below. It is not the official implementation
> artifact of the publication, and is shared here for educational and research purposes.**

## Origin

This code reconstructs the cryptographic scheme described in:

> **Ko, K.T.; Hlaing, H.H.; Mambo, M.**  
> *A PEKS-Based NDN Strategy for Name Privacy.*  
> Future Internet 2020, 12(8), 130.  
> https://doi.org/10.3390/fi12080130

The paper was published under the [MDPI open-access license (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
This reconstruction re-implements the scheme independently in C++ using the
[mcl](https://github.com/herumi/mcl) library. No code or text from the published article
is reproduced here — only the mathematical construction described therein.

## What This Reconstruction Does Differently

The original paper describes PEKS using a symmetric bilinear map `e: G1 × G1 → G2`.
This implementation uses the asymmetric optimal **Ate pairing** `e: G1 × G2 → GT` on
**BLS12-381**, which is more efficient and standard in modern pairing libraries.

---

## Scheme

The scheme encrypts individual NDN name components as PEKS ciphertexts. A router holding a trapdoor for a keyword can test whether an encrypted name component matches, without learning anything else.

### Algorithms

| Algorithm | Input | Output | Description |
|---|---|---|---|
| **KeyGen** | — | `(pk, sk)` | Pick α ← ℤp; pk = α·Q ∈ G2; sk = α |
| **Encrypt** | pk, keyword W | `(A, B)` | r ← ℤp; A = r·Q; B = H₂(e(H₁(W), r·pk)) |
| **Trapdoor** | sk, keyword W | `Tw` | Tw = α·H₁(W) ∈ G1 |
| **Test** | `(A, B)`, Tw | `bool` | H₂(e(Tw, A)) == B |

**Correctness:**  
`e(α·H₁(W), r·Q) = e(H₁(W), Q)^(αr) = e(H₁(W), r·α·Q)` ✓

### Hash functions
- **H₁ : {0,1}* → G1** — hash-and-map to G1 (Shallue–van de Woestijne encoding, provided by mcl)
- **H₂ : GT → {0,1}*** — canonical serialization of the Fp12 element (replace with SHA-256 in production)

### Security
Provably secure against chosen-keyword attacks (IND-CKA) in the random oracle model under the **Bilinear Diffie-Hellman (BDH)** assumption on BLS12-381.

---

## Repository Structure

```
.
├── ate_pairing.hpp      # AtePairing class — wraps mcl pairing primitives
├── ate_pairing.cpp
├── ate_pairing_test.cpp # Bilinearity, Miller loop, precomputed, DH tests
│
├── peks.hpp             # PEKS class — KeyGen / Encrypt / Trapdoor / Test
├── peks.cpp
├── peks_test.cpp        # Correctness and NDN name component search tests
│
└── mcl/                 # mcl library (cloned from herumi/mcl)
```

---

## Dependencies

| Dependency | Purpose |
|---|---|
| [mcl](https://github.com/herumi/mcl) | BLS12-381 pairing, field arithmetic |
| libgmp | Multi-precision arithmetic (required by mcl tests) |
| g++ ≥ 7, cmake ≥ 3.10 | Build toolchain |

### Install dependencies (Ubuntu / Debian)
```bash
sudo apt-get install -y libgmp-dev cmake g++
```

---

## Build & Install mcl

```bash
git clone https://github.com/herumi/mcl.git
cd mcl
make -j$(nproc)
sudo make install          # installs to /usr/local
cd ..
```

---

## Build

### Ate pairing layer
```bash
g++ -O2 -std=c++14 -I/usr/local/include \
    ate_pairing.cpp ate_pairing_test.cpp \
    -o ate_pairing_test \
    /usr/local/lib/libmcl.a -lgmp -lgmpxx -lrt
```

### PEKS library + test
```bash
g++ -O2 -std=c++17 -I/usr/local/include \
    ate_pairing.cpp peks.cpp peks_test.cpp \
    -o peks_test \
    /usr/local/lib/libmcl.a -lgmp -lgmpxx -lrt
```

---

## Usage

```cpp
#include "peks.hpp"

AtePairing bp;                          // initialise BLS12-381
PEKS peks(bp);

auto [pk, sk] = peks.keygen();

// Producer: encrypt each NDN name component
PEKS::Ciphertext c = peks.encrypt(pk, "alice");

// Producer: issue trapdoor for a name component
PEKS::Trapdoor td = peks.trapdoor(sk, "alice");

// Router: test without learning the keyword
bool found = peks.test(c, td);          // true
```

### NDN name search example
```cpp
std::vector<std::string> name = {"ndn", "home", "alice", "data", "file1.txt"};

// Encrypt each component
std::vector<PEKS::Ciphertext> enc;
for (const auto& comp : name)
    enc.push_back(peks.encrypt(pk, comp));

// Trapdoor for "alice"
PEKS::Trapdoor td = peks.trapdoor(sk, "alice");

// Router searches
for (size_t i = 0; i < name.size(); ++i)
    if (peks.test(enc[i], td))
        printf("match at component %zu\n", i);   // prints: match at component 2
```

---

## Test Output

```
=== PEKS on BLS12-381 ===

-- Correct keyword --
  encrypt+trapdoor('confidential'): MATCH
  encrypt+trapdoor('alice'): MATCH
  encrypt+trapdoor('/ndn/home'): MATCH

-- Wrong keyword --
  encrypt('confidential') vs trapdoor('public'): NO MATCH (correct)

-- Ciphertext reuse --
  same keyword, fresh trapdoor: MATCH

-- NDN name component search (/ndn/home/alice/data/file1.txt) --
  trapdoor('alice'): found at [2]='alice'
  trapdoor('bob'):
  trapdoor('data'): found at [3]='data'
```

---

## Citation

If you use this code, please cite the original paper:

```bibtex
@article{ko2020peks,
  author    = {Ko, Kyi Thar and Hlaing, Htet Htet and Mambo, Masahiro},
  title     = {A PEKS-Based NDN Strategy for Name Privacy},
  journal   = {Future Internet},
  volume    = {12},
  number    = {8},
  pages     = {130},
  year      = {2020},
  doi       = {10.3390/fi12080130},
  url       = {https://www.mdpi.com/1999-5903/12/8/130}
}
```

---

## References

- Boneh, D.; Di Crescenzo, G.; Ostrovsky, R.; Persiano, G. *Public Key Encryption with Keyword Search.* EUROCRYPT 2004.
- Herumi. *mcl — A portable and fast pairing-based cryptography library.* https://github.com/herumi/mcl
