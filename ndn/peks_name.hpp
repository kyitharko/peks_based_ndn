#pragma once
#include "../peks.hpp"
#include <ndn-cxx/name.hpp>
#include <vector>
#include <string>

// Wire encoding for PEKS types as NDN Name components.
//
// Ciphertext component layout (fixed-prefix encoding on BLS12-381):
//   [ 96 bytes : G2 point A (compressed) ][ N bytes : B (H2 output) ]
//
// Trapdoor layout:
//   [ 48 bytes : G1 point Tw (compressed) ]
//
// PublicKey layout:
//   [ 96 bytes : G2 point pk (compressed) ]

class PeksName {
public:
    static constexpr size_t G1_BYTES = 48;
    static constexpr size_t G2_BYTES = 96;

    // Encode/decode a single PEKS ciphertext as an NDN GenericNameComponent
    static ndn::name::Component encodeComponent(const PEKS::Ciphertext& c);
    static PEKS::Ciphertext     decodeComponent(const ndn::name::Component& comp);

    // Encode/decode a trapdoor as raw bytes (for /shared volume transfer)
    static std::vector<uint8_t> encodeTrapdoor(const PEKS::Trapdoor& td);
    static PEKS::Trapdoor       decodeTrapdoor(const std::vector<uint8_t>& bytes);

    // Encode/decode public key as raw bytes
    static std::vector<uint8_t> encodePublicKey(const PEKS::PublicKey& pk);
    static PEKS::PublicKey      decodePublicKey(const std::vector<uint8_t>& bytes);

    // Build a full NDN name by encrypting each keyword under pk.
    // Returns /[enc(components[0])]/[enc(components[1])]/...
    // Prepend the routing prefix yourself: prefix.append(buildEncryptedSuffix(...))
    static ndn::Name buildEncryptedSuffix(PEKS& peks,
                                          const PEKS::PublicKey& pk,
                                          const std::vector<std::string>& components);
};
