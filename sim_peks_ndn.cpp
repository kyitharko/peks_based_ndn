// sim_peks_ndn.cpp
// Standalone simulation of the PEKS-NDN protocol described in:
//   Ko, K.T.; Hlaing, H.H.; Mambo, M. "Implementing PEKS Schemes Based on
//   Pairing-Based Cryptography" Future Internet 2020, 12(8), 130.
//
// Three nodes are simulated in one process: Producer, Router, Consumer.
// No ndn-cxx or NFD dependency — all NDN packet structures are approximated
// with simple structs so the cryptographic flow is clearly visible.
//
// Protocol flow (Section 3 of the paper):
//   1. Producer: KeyGen() → (pk, sk), Trapdoor(sk, w_i) for each keyword
//   2. Producer distributes pk → Consumer, td_i → Router (via /shared volume)
//   3. Consumer: Encrypt(pk, w_i) per name component → Interest name
//   4. Router (PeksStrategy): Test(c_i, td_i) for each component
//      → forward on all-match, reject on any mismatch
//   5. Producer receives matched Interest, sends Data
//   6. Consumer receives Data

#include "ate_pairing.hpp"
#include "peks.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>

// ─────────────────────────────────────────────────────────────────────────────
// Constants matching PeksName in ndn/peks_name.hpp
// ─────────────────────────────────────────────────────────────────────────────
static constexpr size_t G1_BYTES = 48;
static constexpr size_t G2_BYTES = 96;

// ─────────────────────────────────────────────────────────────────────────────
// Serialization (same logic as ndn/peks_name.cpp, without ndn-cxx types)
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint8_t> serG1(const AtePairing::G1& p)
{
    std::vector<uint8_t> buf(G1_BYTES);
    if (p.serialize(buf.data(), buf.size()) != G1_BYTES)
        throw std::runtime_error("G1 serialize failed");
    return buf;
}

static std::vector<uint8_t> serG2(const AtePairing::G2& p)
{
    std::vector<uint8_t> buf(G2_BYTES);
    if (p.serialize(buf.data(), buf.size()) != G2_BYTES)
        throw std::runtime_error("G2 serialize failed");
    return buf;
}

static AtePairing::G1 deserG1(const std::vector<uint8_t>& b)
{
    AtePairing::G1 p;
    if (!p.deserialize(b.data(), G1_BYTES))
        throw std::runtime_error("G1 deserialize failed");
    return p;
}

static AtePairing::G2 deserG2(const std::vector<uint8_t>& b)
{
    AtePairing::G2 p;
    if (!p.deserialize(b.data(), G2_BYTES))
        throw std::runtime_error("G2 deserialize failed");
    return p;
}

// Ciphertext wire format: [96B G2 A][B bytes]
static std::vector<uint8_t> encodeCiphertext(const PEKS::Ciphertext& c)
{
    auto buf = serG2(c.A);
    buf.insert(buf.end(), c.B.begin(), c.B.end());
    return buf;
}

static PEKS::Ciphertext decodeCiphertext(const std::vector<uint8_t>& buf)
{
    if (buf.size() <= G2_BYTES)
        throw std::runtime_error("Ciphertext buffer too small");
    PEKS::Ciphertext c;
    std::vector<uint8_t> aBytes(buf.begin(), buf.begin() + G2_BYTES);
    c.A = deserG2(aBytes);
    c.B.assign(buf.begin() + G2_BYTES, buf.end());
    return c;
}

static std::vector<uint8_t> encodeTrapdoor(const PEKS::Trapdoor& td)
{
    return serG1(td.Tw);
}

static PEKS::Trapdoor decodeTrapdoor(const std::vector<uint8_t>& b)
{
    PEKS::Trapdoor td;
    td.Tw = deserG1(b);
    return td;
}

static std::vector<uint8_t> encodePublicKey(const PEKS::PublicKey& pk)
{
    return serG2(pk.pk);
}

static PEKS::PublicKey decodePublicKey(const std::vector<uint8_t>& b)
{
    PEKS::PublicKey pk;
    pk.pk = deserG2(b);
    return pk;
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulated NDN structures (no ndn-cxx)
// ─────────────────────────────────────────────────────────────────────────────

// One NDN GenericNameComponent: opaque bytes payload
struct SimComponent {
    std::vector<uint8_t> value;

    std::string shortHex() const {
        std::ostringstream s;
        s << std::hex << std::setfill('0');
        size_t n = std::min(value.size(), (size_t)4);
        for (size_t i = 0; i < n; ++i)
            s << std::setw(2) << (int)value[i];
        if (value.size() > n)
            s << "…";
        s << "(" << std::dec << value.size() << "B)";
        return s.str();
    }
};

// NDN Name: routing prefix + list of GenericNameComponents
struct SimName {
    std::string               prefix;     // e.g. "/peks"
    std::vector<SimComponent> components; // encrypted components

    std::string toString() const {
        std::string s = prefix;
        for (const auto& c : components)
            s += "/[" + c.shortHex() + "]";
        return s;
    }

    size_t size() const { return components.size(); }
};

// Minimal Interest and Data
struct SimInterest {
    SimName name;
};

struct SimData {
    SimName     name;
    std::string content;
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared volume (simulates the Docker /shared bind-mount)
// In Docker: producer writes → router and consumer read from volume.
// ─────────────────────────────────────────────────────────────────────────────
struct SharedVolume {
    std::vector<uint8_t>              pkBytes;       // pk.bin
    std::vector<std::vector<uint8_t>> trapdoorBytes; // td_0.bin, td_1.bin, ...
};

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────
static void section(const std::string& msg)
{
    std::cout << "\n" << std::string(72, '-') << "\n"
              << "  " << msg << "\n"
              << std::string(72, '-') << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// ProducerNode  (peks_producer binary in Docker)
// ─────────────────────────────────────────────────────────────────────────────
class ProducerNode {
public:
    // Searchable keywords that map to the NDN name segments the producer owns.
    // Must match the trapdoors the router receives.
    static const std::vector<std::string> KEYWORDS;

    void setup(SharedVolume& vol)
    {
        section("PRODUCER — KeyGen + Trapdoor  [start-producer.sh]");

        // KeyGen: α ←R Zp*,  pk = α·Q  (Q is a fixed G2 generator inside PEKS)
        auto [generatedPk, generatedSk] = m_peks.keygen();
        m_pk = generatedPk;
        m_sk = generatedSk;

        std::cout << "  KeyGen():\n";
        std::cout << "    α  (secret) = " << m_sk.alpha.getStr(16).substr(0, 20) << "…\n";
        std::cout << "    pk = α·Q  (G2, " << G2_BYTES << " B compressed)\n";

        vol.pkBytes = encodePublicKey(m_pk);
        std::cout << "  → /shared/pk.bin  (" << vol.pkBytes.size() << " B)\n\n";

        // Trapdoor: Tw_i = α·H1(w_i)  for each keyword w_i
        vol.trapdoorBytes.resize(KEYWORDS.size());
        for (size_t i = 0; i < KEYWORDS.size(); ++i) {
            auto td = m_peks.trapdoor(m_sk, KEYWORDS[i]);
            vol.trapdoorBytes[i] = encodeTrapdoor(td);
            std::cout << "  Trapdoor(sk, \"" << KEYWORDS[i] << "\")"
                      << " = α·H1(w)  (G1, " << vol.trapdoorBytes[i].size() << " B)"
                      << " → /shared/td_" << i << ".bin\n";
        }
    }

    // Called when router forwards a matching Interest
    SimData onInterest(const SimInterest& interest)
    {
        std::cout << "\n  [PRODUCER] Interest received: " << interest.name.toString() << "\n";
        SimData data;
        data.name    = interest.name;
        data.content = "Hello from PEKS-NDN Producer! (Ko et al. 2020)";
        std::cout << "  [PRODUCER] Sending Data: \"" << data.content << "\"\n";
        return data;
    }

private:
    AtePairing      m_bp;
    PEKS            m_peks{m_bp};
    PEKS::PublicKey m_pk;
    PEKS::SecretKey m_sk;
};

const std::vector<std::string> ProducerNode::KEYWORDS = {
    "ndn", "home", "alice", "data", "file1"
};

// ─────────────────────────────────────────────────────────────────────────────
// RouterNode  (NFD + PeksStrategy in Docker)
// ─────────────────────────────────────────────────────────────────────────────
class RouterNode {
public:
    void setup(const SharedVolume& vol)
    {
        section("ROUTER — Load Trapdoors  [start-router.sh]");
        std::cout << "  NFD started.  FIB: /peks → producer\n";
        std::cout << "  Strategy: /localhost/nfd/strategy/peks/%FD%01\n\n";

        for (size_t i = 0; i < vol.trapdoorBytes.size(); ++i) {
            m_trapdoors.push_back(decodeTrapdoor(vol.trapdoorBytes[i]));
            std::cout << "  Loaded /shared/td_" << i << ".bin  ("
                      << vol.trapdoorBytes[i].size() << " B)\n";
        }
        std::cout << "  PeksStrategy armed with " << m_trapdoors.size() << " trapdoors.\n";
    }

    // Mimics PeksStrategy::afterReceiveInterest().
    // Returns true → forward to producer.  Returns false → rejectPendingInterest().
    bool testInterest(const SimInterest& interest)
    {
        const SimName& name = interest.name;

        std::cout << "\n  [ROUTER] afterReceiveInterest: " << name.toString() << "\n";
        std::cout << "  [ROUTER] component[0] = \"" << name.prefix.substr(1)
                  << "\" (routing prefix, skip)\n";
        std::cout << "  [ROUTER] Testing " << name.size()
                  << " encrypted component(s) against " << m_trapdoors.size()
                  << " trapdoor(s):\n\n";

        if (m_trapdoors.empty()) {
            std::cout << "  [ROUTER] No trapdoors loaded — REJECT\n";
            return false;
        }
        if (name.size() < m_trapdoors.size()) {
            std::cout << "  [ROUTER] Name has only " << name.size()
                      << " encrypted component(s), need " << m_trapdoors.size()
                      << " — REJECT\n";
            return false;
        }

        for (size_t i = 0; i < m_trapdoors.size(); ++i) {
            PEKS::Ciphertext c = decodeCiphertext(name.components[i].value);

            // PEKS::test: compute e(Tw_i, A_i) and compare H2 with B_i
            bool match = m_peks.test(c, m_trapdoors[i]);
            std::cout << "    PEKS::test(comp[" << i << "], td_" << i << ")  →  "
                      << (match ? "MATCH ✓" : "NO MATCH ✗") << "\n";

            if (!match) {
                std::cout << "\n  [ROUTER] Mismatch at component[" << i
                          << "] — rejectPendingInterest()\n";
                return false;
            }
        }

        std::cout << "\n  [ROUTER] All " << m_trapdoors.size()
                  << " components matched — sendInterest() to producer\n";
        return true;
    }

private:
    AtePairing                  m_bp;
    PEKS                        m_peks{m_bp};
    std::vector<PEKS::Trapdoor> m_trapdoors;
};

// ─────────────────────────────────────────────────────────────────────────────
// ConsumerNode  (peks_consumer binary in Docker)
// ─────────────────────────────────────────────────────────────────────────────
class ConsumerNode {
public:
    void setup(const SharedVolume& vol)
    {
        section("CONSUMER — Load Public Key  [start-consumer.sh]");
        m_pk = decodePublicKey(vol.pkBytes);
        std::cout << "  /shared/pk.bin loaded  (" << vol.pkBytes.size() << " B)\n";
        std::cout << "  pk = α·Q  (G2 point — no secret key needed to encrypt)\n";
    }

    // Encrypts each keyword under pk and builds an NDN Interest name.
    // NDN name: /peks / enc(w_0) / enc(w_1) / …
    SimInterest buildInterest(const std::vector<std::string>& keywords)
    {
        section("CONSUMER — Build Encrypted Interest  [peks_consumer]");

        std::cout << "  Plaintext keywords: [";
        for (size_t i = 0; i < keywords.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << '"' << keywords[i] << '"';
        }
        std::cout << "]\n\n";
        std::cout << "  Encrypt(pk, w_i)  [r ←R Zp*,  A=r·Q,  B=H2(e(H1(w),r·pk))]:\n";

        SimInterest interest;
        interest.name.prefix = "/peks";

        for (size_t i = 0; i < keywords.size(); ++i) {
            auto c     = m_peks.encrypt(m_pk, keywords[i]);
            auto bytes = encodeCiphertext(c);
            std::cout << "    enc(\"" << keywords[i] << "\")"
                      << "  A=" << G2_BYTES << "B  B=" << c.B.size()
                      << "B  total=" << bytes.size() << "B\n";
            SimComponent comp;
            comp.value = bytes;
            interest.name.components.push_back(comp);
        }

        std::cout << "\n  NDN Interest: " << interest.name.toString() << "\n";
        return interest;
    }

private:
    AtePairing      m_bp;
    PEKS            m_peks{m_bp};
    PEKS::PublicKey m_pk;
};

// ─────────────────────────────────────────────────────────────────────────────
// Run one end-to-end scenario
// ─────────────────────────────────────────────────────────────────────────────
static void scenario(const std::string&           title,
                     ConsumerNode&                consumer,
                     RouterNode&                  router,
                     ProducerNode&                producer,
                     const std::vector<std::string>& keywords)
{
    std::cout << "\n╔══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  SCENARIO: " << std::left << std::setw(58) << title << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";

    SimInterest interest = consumer.buildInterest(keywords);
    bool forwarded       = router.testInterest(interest);

    if (forwarded) {
        SimData data = producer.onInterest(interest);
        std::cout << "\n  [CONSUMER] Data received: \"" << data.content << "\"\n";
    } else {
        std::cout << "\n  [CONSUMER] Interest rejected — no Data (timeout).\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║   PEKS-NDN Simulation  (Ko et al., Future Internet 2020, 12(8),130)║\n";
    std::cout << "║   Ate pairing on BLS12-381  via mcl                                ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";

    // Simulated shared Docker volume (/shared bind-mount)
    SharedVolume vol;

    ProducerNode producer;
    RouterNode   router;
    ConsumerNode consumer;

    // ── Setup phase ──────────────────────────────────────────────────────────
    // Mirrors docker-compose startup order: router depends-on producer
    producer.setup(vol);   // writes pk.bin + td_*.bin to vol
    router.setup(vol);     // reads td_*.bin from vol
    consumer.setup(vol);   // reads pk.bin from vol

    // ── Scenario 1: all keywords correct → Interest FORWARDED ────────────────
    scenario("Correct keywords — Interest FORWARDED",
             consumer, router, producer,
             {"ndn", "home", "alice", "data", "file1"});

    // ── Scenario 2: wrong keyword → Interest REJECTED ────────────────────────
    scenario("Wrong keyword (\"bob\" not \"alice\") — Interest REJECTED",
             consumer, router, producer,
             {"ndn", "home", "bob", "data", "file1"});

    // ── Scenario 3: fewer components than trapdoors → REJECTED ───────────────
    scenario("Incomplete name (4 components, need 5) — Interest REJECTED",
             consumer, router, producer,
             {"ndn", "home", "alice", "data"});

    // ── Scenario 4: ciphertext freshness — different r each time ─────────────
    // Two encryptions of the same keyword produce different (A,B) but still match.
    section("BONUS: Ciphertext freshness — different r each run");
    {
        auto c1 = consumer.buildInterest({"ndn", "home", "alice", "data", "file1"});
        auto c2 = consumer.buildInterest({"ndn", "home", "alice", "data", "file1"});
        bool same = (c1.name.components[0].value == c2.name.components[0].value);
        std::cout << "\n  Two encryptions of the same name: "
                  << (same ? "IDENTICAL (bad!)" : "DIFFERENT bytes ✓  (r is re-randomised each time)") << "\n";
        std::cout << "  Both still route correctly:\n";
        bool ok1 = router.testInterest(c1);
        bool ok2 = router.testInterest(c2);
        std::cout << "  Interest 1 forwarded: " << (ok1 ? "YES ✓" : "NO ✗") << "\n";
        std::cout << "  Interest 2 forwarded: " << (ok2 ? "YES ✓" : "NO ✗") << "\n";
    }

    section("Simulation complete — protocol summary");
    std::cout << "  ┌───────────────┬────────────────────────────────────────────────┐\n";
    std::cout << "  │ Node          │ Operation                                      │\n";
    std::cout << "  ├───────────────┼────────────────────────────────────────────────┤\n";
    std::cout << "  │ Producer      │ KeyGen() → (pk,sk)                             │\n";
    std::cout << "  │               │ Trapdoor(sk, w_i) → Tw_i = α·H1(w_i) ∈ G1    │\n";
    std::cout << "  │ Consumer      │ Encrypt(pk, w_i) → (A=r·Q, B=H2(e(H1(w),r·pk)))│\n";
    std::cout << "  │ Router        │ Test(A_i,B_i, Tw_i): H2(e(Tw_i,A_i)) == B_i? │\n";
    std::cout << "  │ Producer      │ Data reply on all-match                        │\n";
    std::cout << "  └───────────────┴────────────────────────────────────────────────┘\n";
    std::cout << "\n  Pairing correctness:\n";
    std::cout << "    e(Tw_i, A_i) = e(α·H1(w_i), r·Q)\n";
    std::cout << "               = e(H1(w_i), Q)^(αr)\n";
    std::cout << "    B_i         = H2(e(H1(w_i), r·pk))\n";
    std::cout << "               = H2(e(H1(w_i), r·α·Q))\n";
    std::cout << "               = H2(e(H1(w_i), Q)^(αr))  ← same exponent\n";
    std::cout << std::endl;

    return 0;
}
