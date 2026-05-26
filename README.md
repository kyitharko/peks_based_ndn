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

---

## Contents

- [Cryptographic Scheme](#scheme)
- [NDN Integration](#ndn-integration)
  - [Roles: Producer, Router, Consumer](#roles)
  - [Interest Name Format](#interest-name-format)
  - [Data Flow](#data-flow)
  - [Algorithm: ExactMatch / LongestMatch](#algorithm-exactmatch--longestmatch)
  - [Memoised Pairing Tests](#memoised-pairing-tests)
  - [Startup Sequence and Ready Flags](#startup-sequence-and-ready-flags)
- [Topology — Figure 10 (Ko et al. 2020)](#topology--figure-10-ko-et-al-2020)
- [Docker Quickstart](#docker-quickstart)
- [Configuration Reference](#configuration-reference)
- [Repository Structure](#repository-structure)
- [Generating documentation](#generating-documentation)
- [Build (standalone)](#build-standalone)
- [What This Reconstruction Does Differently](#what-this-reconstruction-does-differently)
- [Citation](#citation)

---

## Scheme

The scheme encrypts individual NDN name components as PEKS ciphertexts. A router holding
a trapdoor for a keyword can test whether an encrypted name component matches, without
learning anything else.

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
- **H₂ : GT → {0,1}⁵¹²** — SHA-512 of the canonical 576-byte serialisation of the Fp12 GT element

### Security
Provably secure against chosen-keyword attacks (IND-CKA) in the random oracle model under the
**Bilinear Diffie-Hellman (BDH)** assumption on BLS12-381.

---

## NDN Integration

### Roles

```
┌──────────────────────────────────────────────────────────────────────┐
│  PRODUCER                                                            │
│  ─────────                                                           │
│  • Runs PEKS KeyGen → writes pk.bin to /shared volume               │
│  • Builds 2D trapdoor table: td_{row}_{col}.bin, one per URI        │
│    component. Row = registered URI, Col = component index.           │
│  • After prefix registration with NFD, writes td_ready.flag         │
│  • Listens on /producer/peks_strategy for Interests                  │
│  • On Interest: re-runs PEKS Test to identify matching URI,          │
│    returns Data packet with payload "Data for /uri/path"             │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  ROUTER (NFD + PeksStrategy plugin)                                  │
│  ──────────────────────────────────                                  │
│  • Waits for td_ready.flag, then loads the full 2D trapdoor table   │
│  • Adds FIB route: /producer → upstream face                         │
│  • Registers PeksStrategy on /producer/peks_strategy                 │
│  • Writes router_ready.flag to signal consumers                       │
│  • On every Interest for /producer/peks_strategy/…:                  │
│      – Decodes PEKS ciphertexts from Interest name components        │
│      – Runs ExactMatch / LongestMatch search (Algorithm 1)           │
│      – Forwards to upstream on match; rejects on no match            │
│  • Interest for /producer (without peks_strategy): normal BestRoute  │
│  • Caches Data in NDN Content Store — second Interest for same name  │
│    is served from cache without re-running PEKS Test                 │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  CONSUMER                                                            │
│  ────────                                                            │
│  • Loads pk.bin from /shared volume                                  │
│  • Reads names.txt and selects URIs to request                       │
│  • Encrypts each plaintext name component with PEKS: Encrypt(pk, Ci) │
│  • Builds Interest name: /producer/peks_strategy/C1/C2/.../Ck       │
│  • Sends each Interest TWICE (same encrypted bytes) to demonstrate:  │
│      Round 1 → router PEKS test → forwarded to producer              │
│      Round 2 → router Content Store cache hit (PEKS skipped)         │
│  • Reports total download time and per-URI average                   │
└──────────────────────────────────────────────────────────────────────┘
```

### Interest Name Format

```
/producer / peks_strategy / C1 / C2 / ... / Ck
     │            │          └──────────────────┘
     │            │          PEKS ciphertexts
     │            │          One per plaintext name component.
     │            │          Each Ci = Encrypt(pk, component_i)
     │            │          Wire format: 96-byte G2 point A ‖ 64-byte hash B
     │            │
     │            └── Strategy marker
     │                Tells NFD to invoke PeksStrategy on this Interest.
     │                Any Interest without this component uses BestRoute.
     │
     └── Routing prefix
         NDN FIB entry routes /producer → producer node.
         Consumers and routers all install this route.
```

**Example:** plaintext URI `/google/staff/alice` →
```
/producer/peks_strategy/<Encrypt(pk,"google")>/<Encrypt(pk,"staff")>/<Encrypt(pk,"alice")>
```
Each `<…>` component is 160 bytes (96 + 64), encoded as a GenericNameComponent.

### Data Flow

```
Consumer                Router (PeksStrategy)          Producer
   │                           │                           │
   │  Interest                 │                           │
   │  /producer/peks_strategy/ │                           │
   │  C1/C2/C3                 │                           │
   │──────────────────────────>│                           │
   │                           │ decode C1,C2,C3           │
   │                           │ Test(C1, td[row][0])      │
   │                           │  hit → Test(C2, td[row][1])│
   │                           │   hit → Test(C3, td[row][2])│
   │                           │    ExactMatch row=7        │
   │                           │ forward Interest          │
   │                           │──────────────────────────>│
   │                           │                           │ identifyName()
   │                           │                           │ sign + send Data
   │                           │           Data            │
   │                           │<──────────────────────────│
   │                           │ cache in CS               │
   │         Data              │                           │
   │<──────────────────────────│                           │
   │                           │                           │
   │  Interest (same bytes)    │                           │
   │──────────────────────────>│                           │
   │                           │ CS cache HIT              │
   │         Data (from CS)    │ PeksStrategy NOT invoked  │
   │<──────────────────────────│                           │
```

### Algorithm: ExactMatch / LongestMatch

Algorithm 1 from Ko et al. 2020, as implemented in `ndn/peks_strategy.cpp`:

1. For each row `r` in the trapdoor table:
   - Test `(C1, td[r][0])`. If false → skip row.
   - Test `(C2, td[r][1])`, `(C3, td[r][2])`, … until mismatch or row exhausted.
   - Track match count.
2. **ExactMatch**: row has the same number of components as the Interest, and all match → forward immediately.
3. **LongestMatch**: no exact match found → use the row with the most consecutive matches from component 0.
4. If no row matched even component 0 → reject the Interest (NACK).

The trapdoor table is sorted so rows with longer common prefixes are adjacent, enabling
the memoisation optimisation below to skip the most pairings.

### Memoised Pairing Tests

When multiple registered URIs share a common prefix (e.g. `/google/staff/director` and
`/google/staff/director/md`), their trapdoor tables contain identical G1 points for
the shared columns. An Ate pairing on BLS12-381 is expensive (~1 ms); repeating the
same computation is wasteful.

**Cache key:** 8-byte little-endian column index ‖ serialised trapdoor bytes (48 bytes G1).  
**Cache value:** `bool` result of `Test(Ci, td)`.

```
Interest: C1 / C2 / C3
Trapdoor table:
  Row 0: [tw_google, tw_staff, tw_director]
  Row 1: [tw_google, tw_staff, tw_director, tw_md]
  Row 2: [tw_google, tw_staff, tw_engineer, tw_senior]

Processing:
  Row 0: Test(C1, tw_google) → new pairing → ✓ (cached)
         Test(C2, tw_staff)  → new pairing → ✓ (cached)
         Test(C3, tw_director) → new pairing → ✓  ExactMatch
  Row 1: Test(C1, tw_google) → cache HIT ✓ (no pairing)
         Test(C2, tw_staff)  → cache HIT ✓ (no pairing)
         (Interest has only 3 components, row has 4 → length mismatch)
  Row 2: Test(C1, tw_google) → cache HIT ✓
         Test(C2, tw_staff)  → cache HIT ✓
         Test(C3, tw_engineer) → new pairing → ✗ (skip)

  Total pairings: 4   Cache hits: 4   (vs 9 without caching)
```

The router logs `pairings=X cacheHits=Y rows=N` per Interest so the saving is visible.

### Startup Sequence and Ready Flags

The two-flag protocol guarantees that Interests only arrive after everything is ready:

```
Producer ──[writes pk.bin + trapdoor table]──────────────────────┐
         ──[registers prefix with NFD]                            │
         ──[success callback] → writes td_ready.flag ────────────┤
                                                                  │
Router ──[waits for td_ready.flag] ──[loads trapdoor table]      │
       ──[nfdc route add /producer → upstream]                   │
       ──[nfdc strategy set /producer/peks_strategy peks]        │
       ──[writes router_ready.flag] ─────────────────────────────┤
                                                                  │
Consumer ──[waits for router_ready.flag] ──[loads pk.bin]        │
         ──[encrypts URIs] ──[sends Interests] ──────────────────┘
```

`td_ready.flag` is written inside NFD's prefix-registration **success callback**, not
the constructor. If written earlier there is a race where a router sees the flag and
forwards Interests before the producer's NFD has registered the prefix.

---

## Topology — Figure 10 (Ko et al. 2020)

```
            Producer (10.10.0.10)
                    │
                   R1 (10.10.0.11)
                  /  \
        R2 (10.10.0.12)  R3 (10.10.0.13)
        /    \               /    \
  R4(10.10.0.14) Con1   Con2  R5(10.10.0.15)
      │          (0.21) (0.22)       │
    Con3                           Con4
   (0.23)                         (0.24)
```

| Node | IP | Role |
|---|---|---|
| Producer | 10.10.0.10 | Data source; key + trapdoor authority |
| R1 | 10.10.0.11 | Upstream for R2 and R3 |
| R2 | 10.10.0.12 | Upstream for R4 and Con1 |
| R3 | 10.10.0.13 | Upstream for R5 and Con2 |
| R4 | 10.10.0.14 | Upstream for Con3 |
| R5 | 10.10.0.15 | Upstream for Con4 |
| Con1 | 10.10.0.21 | Requests **all** URIs (Section 5.2 primary requestor) |
| Con2 | 10.10.0.22 | Requests 5 random URIs |
| Con3 | 10.10.0.23 | Requests 5 random URIs |
| Con4 | 10.10.0.24 | Requests 5 random URIs |

**Section 5.2 experiment:** Con1 requests every content name in ℕ (the full registry).
Each URI is sent twice — the second request demonstrates that the router's Content Store
serves the cached Data without re-running the PEKS algorithm.

---

## Docker Quickstart

### Requirements
- Docker ≥ 24 with Compose V2

### Build and run

```bash
docker compose -f docker/docker-compose.yml up --build
```

This builds one image per role (`peks-producer`, `peks-router`, `peks-consumer`) and
starts all 10 containers (1 producer + 5 routers + 4 consumers) on a bridged network.

### Expected output (excerpt)

```
producer  | [PRODUCER] Loaded 103 data names from /data/names.txt
producer  | [PRODUCER] Trapdoor table written: 103 rows, 412 trapdoors total
producer  | [PRODUCER] Prefix registered — td_ready.flag written.
r1        | [r1] Trapdoor table ready.
r1        | [r1] router_ready.flag written — consumers may start.
con1      | [CON1] Requesting ALL 103 URIs from /data/names.txt (total pool: 103)
con1      | [CON1] ── Query 1/103  Round 1/2 ──
con1      | [CON1] URI : /google/staff/director
con1      | [CON1] ← [PRODUCER] Data for /google/staff/director  [Ko et al. 2020 PEKS-NDN]
con1      | [CON1] ── Query 1/103  Round 2/2 ──
con1      | [CON1] ← [ROUTER CS] Data for /google/staff/director  [Ko et al. 2020 PEKS-NDN]
...
con1      | [CON1] Total download time : 42.317 s
con1      | [CON1] Avg per URI         : 0.411 s
```

Router strategy log (set `NDN_LOG=peks.strategy=INFO`):
```
r1  | Search done: pairings=6 cacheHits=12 rows=103
r1  | ExactMatch row=0 components=3 pairings=6 cacheHits=12 — forwarding: /producer/…
```

### Tear down

```bash
docker compose -f docker/docker-compose.yml down -v
```

The `-v` flag removes the `shared_keys` volume so the next run starts clean.

---

## Configuration Reference

All configuration is via environment variables set in `docker/docker-compose.yml`.

### Producer

| Variable | Default | Description |
|---|---|---|
| `NAMES_FILE` | `/data/names.txt` | Path to URI registry |
| `SHARE_DIR` | `/shared` | Volume path for pk.bin / trapdoors / flags |

### Router

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_IP` | *(required)* | IP of the next-hop router or producer |
| `TRAPDOOR_DIR` | `/shared` | Volume path to load trapdoor table from |
| `NDN_LOG` | — | e.g. `peks.strategy=INFO:nfd.Forwarder=WARN` |

### Consumer

| Variable | Default | Description |
|---|---|---|
| `ROUTER_IP` | *(required)* | IP of the directly-connected router |
| `NAMES_FILE` | `/data/names.txt` | URI list to request from |
| `QUERY_COUNT` | `5` | Number of URIs to request; `0` = all |
| `CONSUMER_ID` | `?` | Label printed in output (e.g. `1`, `2`) |
| `SHARE_DIR` | `/shared` | Volume path to read pk.bin from |

---

## Repository Structure

```
.
├── ate_pairing.hpp          # AtePairing class — wraps mcl Ate pairing primitives
├── ate_pairing.cpp
├── ate_pairing_test.cpp     # Bilinearity, Miller loop, precomputed, DH tests
│
├── peks.hpp                 # PEKS class — KeyGen / Encrypt / Trapdoor / Test
├── peks.cpp
├── peks_test.cpp            # Correctness and NDN name component search tests
│
├── ndn/
│   ├── CMakeLists.txt       # Builds producer, consumer, PeksStrategy NFD plugin
│   ├── peks_name.hpp        # Wire encoding: PEKS types ↔ NDN Name components
│   ├── peks_name.cpp
│   ├── producer.cpp         # NDN producer: KeyGen, trapdoor table, serve Data
│   ├── consumer.cpp         # NDN consumer: encrypt URIs, send Interests, timing
│   ├── peks_strategy.hpp    # NFD forwarding strategy declaration
│   ├── peks_strategy.cpp    # ExactMatch/LongestMatch + memoised pairing tests
│   └── names.txt            # Local copy of URI registry (mounted to /data)
│
├── data/
│   └── names.txt            # 103 URIs with prefix hierarchies
│
├── docker/
│   ├── Dockerfile           # Multi-stage: builder → runtime-base → producer/router/consumer
│   ├── docker-compose.yml   # Figure 10 topology: 1 producer, 5 routers, 4 consumers
│   └── scripts/
│       ├── start-producer.sh
│       ├── start-router.sh
│       └── start-consumer.sh
│
├── sim_peks_ndn.cpp         # Standalone simulation (no NDN stack required)
├── CMakeLists.txt
└── mcl/                     # mcl library (cloned from herumi/mcl)
```

---

## Generating documentation

API documentation is generated with [Doxygen](https://www.doxygen.nl/).

### Install Doxygen
```bash
# Ubuntu / Debian
sudo apt-get install -y doxygen

# macOS
brew install doxygen
```

### Generate and open
```bash
doxygen Doxyfile
# HTML output → docs/html/index.html
xdg-open docs/html/index.html   # Linux
open      docs/html/index.html   # macOS
```

The `mcl/` and `build/` directories are excluded automatically.
The README is used as the main page.

---

## Build (standalone)

The standalone PEKS library and simulation do not require NDN. The NDN integration
requires ndn-cxx and NFD headers; those are handled by the Docker build.

### Dependencies

| Dependency | Purpose |
|---|---|
| [mcl](https://github.com/herumi/mcl) | BLS12-381 pairing, field arithmetic |
| libgmp | Multi-precision arithmetic (required by mcl) |
| g++ ≥ 7, cmake ≥ 3.10 | Build toolchain |

```bash
sudo apt-get install -y libgmp-dev cmake g++
```

### Install mcl

```bash
git clone https://github.com/herumi/mcl.git
cd mcl
make -j$(nproc)
sudo make install
cd ..
```

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

### Standalone NDN simulation

```bash
g++ -O2 -std=c++17 -I/usr/local/include \
    ate_pairing.cpp peks.cpp sim_peks_ndn.cpp \
    -o sim_peks_ndn \
    /usr/local/lib/libmcl.a -lgmp -lgmpxx -lrt
./sim_peks_ndn
```

### API usage

```cpp
#include "peks.hpp"

AtePairing bp;
PEKS peks(bp);

auto [pk, sk] = peks.keygen();

// Encrypt a name component
PEKS::Ciphertext c = peks.encrypt(pk, "alice");

// Derive trapdoor for a keyword
PEKS::Trapdoor td = peks.trapdoor(sk, "alice");

// Test without learning the keyword
bool match = peks.test(c, td);   // true
```

---

## What This Reconstruction Does Differently

### 1. Pairing group

The original paper describes PEKS using a symmetric bilinear map `e: G1 × G1 → G2`.
This implementation uses the asymmetric optimal **Ate pairing** `e: G1 × G2 → GT` on
**BLS12-381**, which is more efficient and standard in modern pairing libraries.

### 2. H₂ — cryptographic hash of GT

The paper specifies H₂ as a hash function `GT → {0,1}*`.
This implementation uses **SHA-512** of the canonical 576-byte serialisation of the
Fp12 element, producing a 64-byte uniform digest. This is a concrete instantiation of
the random-oracle H₂ assumed in the paper.

### 3. NDN Interest name structure

The paper describes the Interest name as carrying PEKS ciphertexts but does not fix
the exact NDN name layout. This implementation uses the following structure:

```
/producer / peks_strategy / C1 / C2 / ... / Ck
     │            │          └──────────────┘
     │            │          PEKS ciphertexts  (one per plaintext name component)
     │            └── strategy marker: signals that PEKS algorithm must be applied
     └── routing prefix: NDN FIB routes this Interest to the producer node
```

**Why the two-part prefix?**

- `/producer` is the **routing prefix** — it exists solely so that NDN's FIB can
  forward the Interest to the correct producer node.
- `peks_strategy` is the **algorithm marker** — it is registered as the strategy
  prefix in NFD (`nfdc strategy set /producer/peks_strategy peks`). Any Interest
  whose name contains this component triggers the PEKS ExactMatch/LongestMatch
  search at the router.
- An Interest addressed to `/producer` *without* `peks_strategy` (e.g.
  `/producer/status`) uses normal NDN forwarding (BestRoute) — the PEKS algorithm
  is never invoked.

This separation keeps the routing concern and the privacy-enforcement concern cleanly
distinct, and matches the spirit of the paper's design where PEKS-awareness is
opt-in per Interest.

### 4. Trapdoor pre-distribution via shared volume

The paper describes trapdoors being disseminated from the producer to routers along
the Interest path. In this Docker-based prototype, the producer writes the full 2D
trapdoor table (`td_{row}_{col}.bin`) to a shared volume at startup, and the router
loads the complete table before accepting any Interests. This is equivalent to the
paper's dissemination model but uses a shared filesystem rather than a network
protocol, which is appropriate for a single-machine evaluation setup.

### 5. Memoised pairing tests (algorithmic optimisation)

When multiple registered names share a common prefix (e.g. `/google/cloud/…` entries),
the router's trapdoor table contains identical G1 points for those shared components.
This implementation caches the result of each `Test(Ci, Twij)` call keyed by
`(column index, trapdoor bytes)`. On a cache hit the Ate pairing is skipped entirely.
This optimisation is not described in the paper but is consistent with it — it only
avoids redundant computation, not any cryptographic step.

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
