#pragma once
#include "../peks.hpp"
#include <ndn-cxx/name.hpp>
#include <vector>
#include <string>

/**
 * @file peks_name.hpp
 * @brief Wire encoding for PEKS types as NDN Name components and binary files.
 */

/**
 * @class PeksName
 * @brief Static helpers that serialize/deserialize PEKS types for NDN transport.
 *
 * ### Wire layouts (BLS12-381, all fields compressed)
 *
 * | Type        | Layout | Total size |
 * |-------------|--------|-----------|
 * | Ciphertext  | 96-byte G2 point `A` ‖ 64-byte hash `B` | 160 bytes |
 * | Trapdoor    | 48-byte G1 point `Tw` | 48 bytes |
 * | PublicKey   | 96-byte G2 point `pk` | 96 bytes |
 *
 * ### NDN Name structure
 *
 * The consumer builds a Name by prepending the routing prefix to the
 * encrypted suffix:
 * @code
 * ndn::Name name("/producer/peks_strategy");
 * name.append(PeksName::buildEncryptedSuffix(peks, pk, {"google", "staff", "alice"}));
 * // → /producer/peks_strategy/<Enc("google")>/<Enc("staff")>/<Enc("alice")>
 * @endcode
 *
 * Each encrypted component is a GenericNameComponent carrying 160 raw bytes.
 *
 * ### File layout (shared volume)
 *
 * | File | Content |
 * |------|---------|
 * | `pk.bin` | 96-byte public key |
 * | `td_{row}_{col}.bin` | 48-byte trapdoor for component `col` of URI `row` |
 * | `td_ready.flag` | 1-byte sentinel — present when the table is complete |
 * | `router_ready.flag` | 1-byte sentinel — present when the router is ready |
 */
class PeksName {
public:
    static constexpr size_t G1_BYTES = 48; ///< Compressed G1 point size in bytes.
    static constexpr size_t G2_BYTES = 96; ///< Compressed G2 point size in bytes.

    /** @name NDN Name component encoding */
    ///@{

    /**
     * @brief Encode a PEKS ciphertext as a GenericNameComponent.
     *
     * Serialises `c.A` (96 bytes) followed by `c.B` (64 bytes) and wraps
     * the 160-byte buffer in an NDN GenericNameComponent TLV.
     *
     * @param c Ciphertext to encode.
     * @return NDN name component carrying the ciphertext bytes.
     */
    static ndn::name::Component encodeComponent(const PEKS::Ciphertext& c);

    /**
     * @brief Decode a GenericNameComponent back to a PEKS ciphertext.
     *
     * @param comp NDN name component (must be ≥ 160 bytes).
     * @return Decoded ciphertext.
     * @throws std::runtime_error if the component is too short or G2 deserialization fails.
     */
    static PEKS::Ciphertext decodeComponent(const ndn::name::Component& comp);

    ///@}

    /** @name Binary file encoding (shared volume) */
    ///@{

    /**
     * @brief Serialize a trapdoor to a 48-byte byte vector for file storage.
     * @param td Trapdoor to encode.
     * @return 48-byte G1 serialization of `td.Tw`.
     */
    static std::vector<uint8_t> encodeTrapdoor(const PEKS::Trapdoor& td);

    /**
     * @brief Deserialize a trapdoor from a byte vector read from a `.bin` file.
     * @param bytes Must be exactly G1_BYTES (48) bytes.
     * @return Decoded trapdoor.
     * @throws std::runtime_error if the buffer is too short or deserialization fails.
     */
    static PEKS::Trapdoor decodeTrapdoor(const std::vector<uint8_t>& bytes);

    /**
     * @brief Serialize the public key to a 96-byte byte vector.
     * @param pk Public key to encode.
     * @return 96-byte G2 serialization of `pk.pk`.
     */
    static std::vector<uint8_t> encodePublicKey(const PEKS::PublicKey& pk);

    /**
     * @brief Deserialize the public key from a byte vector read from `pk.bin`.
     * @param bytes Must be exactly G2_BYTES (96) bytes.
     * @return Decoded public key.
     * @throws std::runtime_error if the buffer is too short or deserialization fails.
     */
    static PEKS::PublicKey decodePublicKey(const std::vector<uint8_t>& bytes);

    ///@}

    /** @name Name builder */
    ///@{

    /**
     * @brief Encrypt each component and return them as an NDN Name suffix.
     *
     * Calls PEKS::encrypt() once per component. The result is meant to be
     * appended to a routing prefix:
     * @code
     * ndn::Name name(ROUTING_PREFIX);
     * name.append(PeksName::buildEncryptedSuffix(peks, pk, components));
     * @endcode
     *
     * @param peks       Initialised PEKS instance.
     * @param pk         Public key used for encryption.
     * @param components Plaintext URI components, e.g. `{"google", "staff", "alice"}`.
     * @return NDN Name containing one encrypted component per input string.
     */
    static ndn::Name buildEncryptedSuffix(PEKS& peks,
                                          const PEKS::PublicKey& pk,
                                          const std::vector<std::string>& components);

    ///@}
};
