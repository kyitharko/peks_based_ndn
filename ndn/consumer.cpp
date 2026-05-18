#include "peks_name.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <algorithm>

NDN_LOG_INIT(peks.consumer);

// Strategy Name marker — must match producer and router config.
// Interest format: /peks_strategy/C1/C2/.../Ck  where Ci = PEKS(P_pub, N_i)
static const std::string ROUTING_PREFIX = "/producer";

// ── URI helpers ──────────────────────────────────────────────────────────────

static std::vector<std::string> parseUri(const std::string& uri)
{
    std::vector<std::string> comps;
    std::stringstream ss(uri);
    std::string tok;
    while (std::getline(ss, tok, '/'))
        if (!tok.empty()) comps.push_back(tok);
    return comps;
}

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

// ── Consumer ─────────────────────────────────────────────────────────────────

class Consumer {
public:
    Consumer(const std::string& shareDir,
             const std::string& namesFile,
             int queryCount)
        : m_shareDir(shareDir)
        , m_peks(m_bp)
    {
        // Load public key
        std::ifstream f(shareDir + "/pk.bin", std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open " + shareDir + "/pk.bin");
        std::vector<uint8_t> pkBytes(std::istreambuf_iterator<char>(f), {});
        m_pk = PeksName::decodePublicKey(pkBytes);
        NDN_LOG_INFO("Public key loaded (" << pkBytes.size() << " bytes)");

        // Read all URIs and pick 'queryCount' at random
        auto allNames = readNamesFile(namesFile);
        if (allNames.empty())
            throw std::runtime_error("No URIs loaded from " + namesFile);

        std::mt19937 rng(std::random_device{}());
        std::shuffle(allNames.begin(), allNames.end(), rng);
        int count = std::min(queryCount, static_cast<int>(allNames.size()));

        // Encrypt each selected URI ONCE and store.
        // Reusing the same encrypted name for both Interests is what enables
        // the router's Content Store to serve the second Interest from cache.
        for (int i = 0; i < count; ++i) {
            const auto& comps = allNames[i];
            ndn::Name encName(ROUTING_PREFIX);
            encName.append(PeksName::buildEncryptedSuffix(m_peks, m_pk, comps));
            m_queries.push_back({comps, encName});
        }

        std::cout << "[CONSUMER] Selected " << count << " random URIs from "
                  << namesFile << " (total pool: " << allNames.size() << ")\n";
        NDN_LOG_INFO("Prepared " << count << " queries");
    }

    void run()
    {
        if (m_queries.empty()) {
            std::cout << "[CONSUMER] No queries to send.\n";
            return;
        }

        std::cout << "\n[CONSUMER] ════ Starting experiment ════\n"
                  << "[CONSUMER] Each URI is sent TWICE:\n"
                  << "[CONSUMER]   Round 1 → router PEKS test → producer\n"
                  << "[CONSUMER]   Round 2 → router CS cache (PeksStrategy skipped)\n\n";

        sendNext();
        m_face.processEvents(ndn::time::seconds(300));
    }

private:
    struct Query {
        std::vector<std::string> components;
        ndn::Name                encryptedName;
    };

    void sendNext()
    {
        if (m_queryIdx >= m_queries.size()) {
            std::cout << "\n[CONSUMER] ════ All " << m_queries.size()
                      << " queries complete ════\n";
            NDN_LOG_INFO("All queries complete");
            m_face.shutdown();
            return;
        }

        const auto& q   = m_queries[m_queryIdx];
        std::string uri = joinUri(q.components);
        ++m_round;

        std::cout << "\n[CONSUMER] ── Query " << (m_queryIdx + 1)
                  << "/" << m_queries.size()
                  << "  Round " << m_round << "/2 ──\n"
                  << "[CONSUMER] URI : " << uri << "\n";

        if (m_round == 1)
            std::cout << "[CONSUMER] Sending → router (PEKS test) → producer\n";
        else
            std::cout << "[CONSUMER] Sending → router (CS cache HIT expected)\n";

        ndn::Interest interest(q.encryptedName);
        interest.setMustBeFresh(true);
        interest.setInterestLifetime(ndn::time::seconds(8));

        NDN_LOG_INFO("Interest #" << (m_queryIdx * 2 + m_round)
                     << " round=" << m_round << " uri=" << uri);

        m_face.expressInterest(
            interest,

            // Data callback
            [this, uri](const ndn::Interest&, const ndn::Data& data) {
                std::string content(
                    reinterpret_cast<const char*>(data.getContent().value()),
                    data.getContent().value_size());

                std::string src = (m_round == 2) ? "ROUTER CS" : "PRODUCER";
                std::cout << "[CONSUMER] ← [" << src << "] " << content << "\n";
                NDN_LOG_INFO("Round " << m_round << " data from " << src
                             << ": " << content);

                if (m_round < 2) {
                    sendNext();         // same URI, second round
                } else {
                    m_round = 0;
                    ++m_queryIdx;
                    sendNext();         // next URI
                }
            },

            // Nack callback
            [this, uri](const ndn::Interest&, const ndn::lp::Nack& nack) {
                std::cout << "[CONSUMER] NACK for " << uri
                          << "  reason=" << nack.getReason() << "\n";
                NDN_LOG_WARN("Nack uri=" << uri
                             << " reason=" << nack.getReason());
                m_round = 0;
                ++m_queryIdx;
                sendNext();
            },

            // Timeout callback
            [this, uri](const ndn::Interest&) {
                std::cout << "[CONSUMER] TIMEOUT for " << uri << "\n";
                NDN_LOG_WARN("Timeout uri=" << uri);
                m_round = 0;
                ++m_queryIdx;
                sendNext();
            }
        );
    }

    AtePairing      m_bp;
    PEKS            m_peks;
    PEKS::PublicKey m_pk;
    ndn::Face       m_face;
    std::string     m_shareDir;

    std::vector<Query> m_queries;
    size_t             m_queryIdx = 0;
    int                m_round    = 0;
};

int main(int argc, char* argv[])
{
    std::string shareDir   = (argc > 1) ? argv[1] : "/shared";
    std::string namesFile  = (argc > 2) ? argv[2] : "/data/names.txt";
    int         queryCount = (argc > 3) ? std::stoi(argv[3]) : 5;

    try {
        Consumer consumer(shareDir, namesFile, queryCount);
        consumer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
