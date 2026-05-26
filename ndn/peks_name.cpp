/**
 * @file peks_name.cpp
 * @brief PeksName wire-encoding implementation: G1/G2 serialize/deserialize helpers.
 */
#include "peks_name.hpp"
#include <stdexcept>

// ── helpers ──────────────────────────────────────────────────────────────────

static std::vector<uint8_t> serializeG1(const AtePairing::G1& p)
{
    std::vector<uint8_t> buf(PeksName::G1_BYTES);
    size_t n = p.serialize(buf.data(), buf.size());
    if (n != PeksName::G1_BYTES)
        throw std::runtime_error("G1 serialize failed");
    return buf;
}

static std::vector<uint8_t> serializeG2(const AtePairing::G2& p)
{
    std::vector<uint8_t> buf(PeksName::G2_BYTES);
    size_t n = p.serialize(buf.data(), buf.size());
    if (n != PeksName::G2_BYTES)
        throw std::runtime_error("G2 serialize failed");
    return buf;
}

static AtePairing::G1 deserializeG1(const uint8_t* data, size_t size)
{
    if (size < PeksName::G1_BYTES)
        throw std::runtime_error("Buffer too small for G1");
    AtePairing::G1 p;
    if (!p.deserialize(data, PeksName::G1_BYTES))
        throw std::runtime_error("G1 deserialize failed");
    return p;
}

static AtePairing::G2 deserializeG2(const uint8_t* data, size_t size)
{
    if (size < PeksName::G2_BYTES)
        throw std::runtime_error("Buffer too small for G2");
    AtePairing::G2 p;
    if (!p.deserialize(data, PeksName::G2_BYTES))
        throw std::runtime_error("G2 deserialize failed");
    return p;
}

// ── Ciphertext ───────────────────────────────────────────────────────────────

ndn::name::Component PeksName::encodeComponent(const PEKS::Ciphertext& c)
{
    auto buf = serializeG2(c.A);               // 96 bytes
    buf.insert(buf.end(), c.B.begin(), c.B.end());
    return ndn::name::Component(buf.data(), buf.size());
}

PEKS::Ciphertext PeksName::decodeComponent(const ndn::name::Component& comp)
{
    const uint8_t* data = comp.value();
    size_t          size = comp.value_size();

    PEKS::Ciphertext c;
    c.A = deserializeG2(data, size);
    c.B.assign(data + G2_BYTES, data + size);
    return c;
}

// ── Trapdoor ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> PeksName::encodeTrapdoor(const PEKS::Trapdoor& td)
{
    return serializeG1(td.Tw);
}

PEKS::Trapdoor PeksName::decodeTrapdoor(const std::vector<uint8_t>& bytes)
{
    PEKS::Trapdoor td;
    td.Tw = deserializeG1(bytes.data(), bytes.size());
    return td;
}

// ── PublicKey ────────────────────────────────────────────────────────────────

std::vector<uint8_t> PeksName::encodePublicKey(const PEKS::PublicKey& pk)
{
    return serializeG2(pk.pk);
}

PEKS::PublicKey PeksName::decodePublicKey(const std::vector<uint8_t>& bytes)
{
    PEKS::PublicKey pk;
    pk.pk = deserializeG2(bytes.data(), bytes.size());
    return pk;
}

// ── Name builder ─────────────────────────────────────────────────────────────

ndn::Name PeksName::buildEncryptedSuffix(PEKS& peks,
                                          const PEKS::PublicKey& pk,
                                          const std::vector<std::string>& components)
{
    ndn::Name name;
    for (const auto& comp : components)
        name.append(encodeComponent(peks.encrypt(pk, comp)));
    return name;
}
