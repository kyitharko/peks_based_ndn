# PEKS-NDN Protocol Notes

This document describes the protocol architecture and message flows in this
reimplementation. For cryptographic design decisions (curve choice, group
placement, hash function selection), see `DESIGN.md`.

## Actors

The protocol has three roles:

- **Producer**: owns content, holds private key, registers prefix trapdoor with
  routers, responds to interests, disseminates reactive trapdoor updates.
- **Router**: holds trapdoor table, PEKS CS, and pending interest tracker.
  Matches interests against trapdoor table, serves from cache when possible,
  forwards otherwise.
- **Consumer**: holds producer's public key, encrypts content names to produce
  interests, receives data packets.

## URI formats

Three URI shapes travel on the network. All share the `/peks_strategy/` prefix
so routers can identify them as PEKS-related.

### Encrypted interest

```
/peks_strategy/<C1>/<C2>/.../<Ck>
```

Sent by consumer. Each `<Ci>` is a base64url-encoded PEKS ciphertext (a G2
point plus a 32-byte SHA-256 hash, ~128 bytes total → 171 characters base64url).
Different requests for the same content produce different bytes because PEKS
encryption is probabilistic.

### Trapdoor prefix registration

```
/peks_strategy/TwReg/<prefix_trapdoor>
```

Sent by producer once during setup. `<prefix_trapdoor>` is the base64url-encoded
trapdoor for the producer's prefix (e.g., Trapdoor("producer")). Routers
receiving this store the prefix trapdoor in their table so they can perform
longest-prefix-match forwarding.

### Reactive trapdoor update

```
/peks_strategy/Tw/<TN1>/<TN2>/.../<TNk>/<hash>
```

Sent by producer as a response to a specific interest, after the data packet
has been delivered. Each `<TNi>` is a base64url-encoded trapdoor. `<hash>` is
the base64url-encoded SHA-256 of the interest URI that this update responds to.
Routers use the hash to look up the pending interest and pair the trapdoor
sequence with the corresponding data packet.

## Message flows

### Setup phase

1. Producer generates keypair.
2. Producer builds its own trapdoor table (name → trapdoor sequence for its content).
3. Producer sends the TwReg URI for its prefix.
4. Router receives TwReg, stores prefix trapdoor in its trapdoor table.
5. Consumer receives the producer's public key (out of band in this
   implementation; the paper's Section 3.3 describes a KEY/PARAM interest flow
   which is not implemented here).

### Cold-path request (first time for a content name)

1. Consumer encrypts the target name and produces an interest URI.
2. Consumer sends interest to router.
3. Router computes SHA-256 of the interest URI, stores (hash, uri) in pending
   tracker.
4. Router decodes the interest, matches against its trapdoor table. The prefix
   trapdoor is found as the longest match; no exact match yet.
5. Router forwards the interest to the producer (FIB routes based on the
   matched prefix trapdoor).
6. Producer decodes the interest, matches against its own table, finds exact
   match, retrieves the data.
7. Producer returns the data packet to the router.
8. Router stages the data packet in temporary storage keyed by the interest hash.
9. Producer sends a trapdoor update URI containing the trapdoor sequence for
   the requested name and the hash of the original interest.
10. Router decodes the trapdoor update, extracts (NameTrapdoor, hash).
11. Router looks up the hash in the pending tracker, retrieves and removes the
    original interest URI.
12. Router looks up the hash in the staged data storage, retrieves and removes
    the data packet.
13. Router inserts (NameTrapdoor, DataPacket) into the PEKS CS.
14. Router inserts the NameTrapdoor into its trapdoor table.
15. Data packet flows back to consumer.

### Warm-path request (subsequent requests for the same content)

1. Consumer encrypts the target name and produces an interest URI. The
   ciphertext bytes differ from the previous request because encryption is
   probabilistic.
2. Consumer sends interest to router.
3. Router computes hash, records in pending tracker.
4. Router matches against trapdoor table, finds exact match (the trapdoor
   added during the previous cold-path request).
5. Router looks up CS with the matched trapdoor sequence, finds cached data.
6. Router removes the pending entry (no forwarding needed) and returns the
   data packet to consumer.

## Router state

The router maintains four data structures:

- **Trapdoor table** (`TrapdoorTable`): stores trapdoor sequences from
  registration and reactive dissemination. Used for interest matching. Sorted
  by trapdoor bytes (for potential future prefix-skip optimization, though
  matching currently uses exhaustive search per paper Algorithm 1).
- **PEKS CS** (`PeksCS`): maps trapdoor sequences to cached data packets.
  Populated reactively after the first successful interest for a content name.
  Dummy implementation: unbounded, no eviction.
- **Pending interest tracker** (`PendingInterests`): maps SHA-256(interest URI)
  → interest URI. Populated when interest arrives; removed when trapdoor update
  arrives (or when interest is served from cache).
- **Staged data storage**: maps SHA-256(interest URI) → DataPacket. Populated
  when data arrives from producer; removed when trapdoor update arrives and CS
  is updated. Currently a HashMap inside the Router struct in
  `examples/end_to_end.rs`.

## Why the hash mapping exists

PEKS interest names are probabilistic — each encryption of the same content
name produces different bytes. This breaks NDN's default assumption that a
router can match a returning data packet to its outgoing interest by name.

The solution: the router computes SHA-256(interest_uri) when the interest is
sent and stores this hash. When the producer disseminates a reactive trapdoor
update, it includes this hash. The router uses it to link the deterministic
trapdoor sequence back to the specific probabilistic interest that triggered
the request, and to the staged data packet awaiting pairing.

Without this mechanism, the router could not correctly pair trapdoor updates
with data packets when multiple concurrent interests are in flight.

## What is not implemented

Beyond the primitives and protocol logic that this library provides, a complete
PEKS-NDN deployment would need:

- **NFD integration**: the C++ Named Forwarding Daemon needs to call this
  library when it encounters `/peks_strategy/` URIs. Options include FFI
  wrapping (this library exposed as a C shared object) or a C++ strategy plugin
  that reimplements the protocol logic on top of the primitives.
- **FIB integration**: routers need to register the trapdoor prefix with a real
  FIB so that interest forwarding follows normal NDN nexthop selection. This
  demo pre-populates FIB behavior (single-hop consumer → router → producer).
- **CS eviction**: the dummy CS grows unbounded. Production deployment needs
  LRU or size-limited eviction.
- **Signed packets**: real NDN packets carry cryptographic signatures. This
  demo omits signatures for simplicity.
- **Public key dissemination flow**: paper Section 3.3 describes a KEY/PARAM
  interest that a consumer uses to fetch a producer's public key. This demo
  initializes the consumer directly with the public key.
- **Multi-router topology and experiments**: the paper's Section 5 measurements
  used a five-router topology on dedicated hardware. Reproducing these
  measurements is future work.
