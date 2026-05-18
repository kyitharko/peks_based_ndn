#include "peks_name.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <fstream>
#include <sstream>
#include <iostream>

NDN_LOG_INIT(peks.producer);

// Interest name prefix — Strategy Name marker from Ko et al. 2020 (Image 2).
// Interest format: /peks_strategy/C1/C2/.../Ck  where Ci = PEKS(P_pub, N_i)
static const std::string ROUTING_PREFIX = "/producer";

// ── URI helpers ──────────────────────────────────────────────────────────────

// Split "/a/b/c" → {"a", "b", "c"}
static std::vector<std::string> parseUri(const std::string& uri)
{
    std::vector<std::string> comps;
    std::stringstream ss(uri);
    std::string tok;
    while (std::getline(ss, tok, '/'))
        if (!tok.empty()) comps.push_back(tok);
    return comps;
}

// Read names.txt; skip blank lines and lines starting with '#'.
static std::vector<std::vector<std::string>> readNamesFile(const std::string& path)
{
    std::vector<std::vector<std::string>> names;
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open names file: " + path);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto comps = parseUri(line);
        if (!comps.empty()) names.push_back(comps);
    }
    return names;
}

static std::string joinUri(const std::vector<std::string>& comps)
{
    std::string s;
    for (const auto& c : comps) s += "/" + c;
    return s;
}

static void saveFile(const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot write " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// ── Producer ─────────────────────────────────────────────────────────────────

class Producer {
public:
    Producer(const std::string& shareDir, const std::string& namesFile)
        : m_shareDir(shareDir)
        , m_peks(m_bp)
    {
        // 1. Load data names from file
        m_dataNames = readNamesFile(namesFile);
        if (m_dataNames.empty())
            throw std::runtime_error("No URIs loaded from " + namesFile);

        std::cout << "[PRODUCER] Loaded " << m_dataNames.size()
                  << " data names from " << namesFile << "\n";
        NDN_LOG_INFO("Loaded " << m_dataNames.size() << " data names");

        // 2. Key generation (Image 1: Key generation)
        auto [pk, sk] = m_peks.keygen();
        m_pk = pk;
        m_sk = sk;
        saveFile(shareDir + "/pk.bin", PeksName::encodePublicKey(m_pk));
        NDN_LOG_INFO("pk.bin written");

        // 3. Build 2D trapdoor table and disseminate to shared volume (Image 1).
        //    td_{row}_{col}.bin = trapdoor for component col of data name row.
        size_t total = 0;
        for (size_t row = 0; row < m_dataNames.size(); ++row) {
            for (size_t col = 0; col < m_dataNames[row].size(); ++col) {
                auto td = m_peks.trapdoor(m_sk, m_dataNames[row][col]);
                saveFile(shareDir + "/td_" + std::to_string(row)
                         + "_" + std::to_string(col) + ".bin",
                         PeksName::encodeTrapdoor(td));
                ++total;
            }
        }

        // 4. Signal that the full table is written (router waits for this)
        saveFile(shareDir + "/td_ready.flag", {0x01});

        std::cout << "[PRODUCER] Trapdoor table written: "
                  << m_dataNames.size() << " rows, "
                  << total << " trapdoors total\n";
        NDN_LOG_INFO("Trapdoor table complete: " << total << " entries");
    }

    void run()
    {
        m_face.setInterestFilter(
            ndn::InterestFilter(ROUTING_PREFIX),
            [this](const ndn::InterestFilter&, const ndn::Interest& interest) {
                onInterest(interest);
            },
            [](const ndn::Name& prefix, const std::string& reason) {
                NDN_LOG_ERROR("Prefix registration failed for "
                              << prefix << ": " << reason);
            });

        std::cout << "[PRODUCER] Listening on " << ROUTING_PREFIX << "\n";
        m_face.processEvents();
    }

private:
    // Identify which data name the Interest matches by re-running PEKS::test()
    // using freshly derived trapdoors (producer holds sk, can derive any td).
    // Returns the plaintext URI string, or empty string on no match.
    std::string identifyName(const ndn::Interest& interest) const
    {
        const ndn::Name& name = interest.getName();
        const size_t offset = 1;  // skip "peks_strategy" component

        std::vector<PEKS::Ciphertext> peksList;
        for (size_t i = offset; i < name.size(); ++i) {
            try { peksList.push_back(PeksName::decodeComponent(name.at(i))); }
            catch (...) { break; }
        }
        if (peksList.empty()) return {};

        for (const auto& comps : m_dataNames) {
            if (peksList.size() != comps.size()) continue;
            bool allMatch = true;
            for (size_t col = 0; col < comps.size(); ++col) {
                auto td = m_peks.trapdoor(m_sk, comps[col]);
                if (!m_peks.test(peksList[col], td)) { allMatch = false; break; }
            }
            if (allMatch) return joinUri(comps);
        }
        return {};
    }

    void onInterest(const ndn::Interest& interest)
    {
        std::string uri = identifyName(interest);
        if (uri.empty()) uri = "(unrecognised)";

        std::cout << "[PRODUCER] Interest received → serving: " << uri << "\n";
        NDN_LOG_INFO("Serving: " << uri);

        std::string payload = "Data for " + uri + "  [Ko et al. 2020 PEKS-NDN]";

        ndn::Data data(interest.getName());
        data.setContent(ndn::make_span(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));
        data.setFreshnessPeriod(ndn::time::seconds(30));
        m_keyChain.sign(data);
        m_face.put(data);

        NDN_LOG_INFO("Data sent for " << uri);
    }

    AtePairing                         m_bp;
    PEKS                               m_peks;
    PEKS::PublicKey                    m_pk;
    PEKS::SecretKey                    m_sk;
    ndn::Face                          m_face;
    ndn::KeyChain                      m_keyChain;
    std::string                        m_shareDir;
    std::vector<std::vector<std::string>> m_dataNames;
};

int main(int argc, char* argv[])
{
    std::string shareDir  = (argc > 1) ? argv[1] : "/shared";
    std::string namesFile = (argc > 2) ? argv[2] : "/data/names.txt";
    try {
        Producer producer(shareDir, namesFile);
        producer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
