/**
 * @file consumer.cpp
 * @brief NDN consumer: encrypt URI components with PEKS and send Interests.
 *
 * Each URI is sent **twice** using identical encrypted name bytes:
 * - Round 1: Interest forwarded by PeksStrategy → producer returns Data.
 * - Round 2: Router Content Store cache hit — PeksStrategy is never invoked.
 *
 * This demonstrates the NDN in-network caching benefit on top of PEKS forwarding.
 * Download time and per-URI average are printed on completion.
 *
 * Arguments (positional, or via Docker env vars):
 * | # | Env var      | Default           | Description |
 * |---|-------------|-------------------|-------------|
 * | 1 | SHARE_DIR   | `/shared`         | Path to shared volume with `pk.bin` |
 * | 2 | NAMES_FILE  | `/data/names.txt` | URI registry text file |
 * | 3 | QUERY_COUNT | `5`               | URIs to request (0 = all) |
 * | 4 | CONSUMER_ID | `?`               | Label for console output |
 */
#include "peks_name.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <chrono>

NDN_LOG_INIT(peks.consumer);

// Strategy Name marker — must match producer and router config.
// Interest format: /peks_strategy/C1/C2/.../Ck  where Ci = PEKS(P_pub, N_i)
static const std::string ROUTING_PREFIX = "/producer/peks_strategy";

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
             int queryCount,
             std::string consumerId)
        : m_shareDir(shareDir)
        , m_id(std::move(consumerId))
        , m_peks(m_bp)
    {
        // Load public key
        std::ifstream f(shareDir + "/pk.bin", std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open " + shareDir + "/pk.bin");
        std::vector<uint8_t> pkBytes(std::istreambuf_iterator<char>(f), {});
        m_pk = PeksName::decodePublicKey(pkBytes);
        NDN_LOG_INFO("Public key loaded (" << pkBytes.size() << " bytes)");

        auto allNames = readNamesFile(namesFile);
        if (allNames.empty())
            throw std::runtime_error("No URIs loaded from " + namesFile);

        // queryCount == 0  →  request ALL names (Section 5.2: Con1 requests ℕ)
        // queryCount  > 0  →  request that many names picked at random
        bool requestAll = (queryCount <= 0);
        int  count      = requestAll
                          ? static_cast<int>(allNames.size())
                          : std::min(queryCount, static_cast<int>(allNames.size()));

        if (!requestAll) {
            std::mt19937 rng(std::random_device{}());
            std::shuffle(allNames.begin(), allNames.end(), rng);
        }

        // Encrypt each selected URI ONCE and store.
        // Reusing the same encrypted name for both Interests is what enables
        // the router's Content Store to serve the second Interest from cache.
        for (int i = 0; i < count; ++i) {
            const auto& comps = allNames[i];
            ndn::Name encName(ROUTING_PREFIX);
            encName.append(PeksName::buildEncryptedSuffix(m_peks, m_pk, comps));
            m_queries.push_back({comps, encName});
        }

        std::cout << "[CON" << m_id << "] "
                  << (requestAll ? "Requesting ALL " : "Selected ")
                  << count
                  << (requestAll ? "" : " random")
                  << " URIs from " << namesFile
                  << " (total pool: " << allNames.size() << ")\n";
        NDN_LOG_INFO("Prepared " << count << " queries");

        m_startTime = std::chrono::steady_clock::now();
    }

    void run()
    {
        if (m_queries.empty()) {
            std::cout << "[CON" << m_id << "] No queries to send.\n";
            return;
        }

        std::cout << "\n[CON" << m_id << "] ════ Starting experiment ════\n"
                  << "[CON" << m_id << "] Each URI is sent TWICE:\n"
                  << "[CON" << m_id << "]   Round 1 → router PEKS test → producer\n"
                  << "[CON" << m_id << "]   Round 2 → router CS cache (PeksStrategy skipped)\n\n";

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
            auto elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - m_startTime).count();
            std::cout << "\n[CON" << m_id << "] ════ All " << m_queries.size()
                      << " queries complete ════\n"
                      << "[CON" << m_id << "] Total download time : "
                      << std::fixed << std::setprecision(3) << elapsed << " s\n"
                      << "[CON" << m_id << "] Avg per URI         : "
                      << std::fixed << std::setprecision(3)
                      << (elapsed / m_queries.size()) << " s\n";
            NDN_LOG_INFO("All queries complete in " << elapsed << " s");
            m_face.shutdown();
            return;
        }

        const auto& q   = m_queries[m_queryIdx];
        std::string uri = joinUri(q.components);
        ++m_round;

        std::cout << "\n[CON" << m_id << "] ── Query " << (m_queryIdx + 1)
                  << "/" << m_queries.size()
                  << "  Round " << m_round << "/2 ──\n"
                  << "[CON" << m_id << "] URI : " << uri << "\n";

        if (m_round == 1)
            std::cout << "[CON" << m_id << "] Sending → router (PEKS test) → producer\n";
        else
            std::cout << "[CON" << m_id << "] Sending → router (CS cache HIT expected)\n";

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
                std::cout << "[CON" << m_id << "] ← [" << src << "] " << content << "\n";
                NDN_LOG_INFO("Round " << m_round << " data from " << src
                             << ": " << content);

                if (m_round < 2) {
                    sendNext();
                } else {
                    m_round = 0;
                    ++m_queryIdx;
                    sendNext();
                }
            },

            // Nack callback
            [this, uri](const ndn::Interest&, const ndn::lp::Nack& nack) {
                std::cout << "[CON" << m_id << "] NACK for " << uri
                          << "  reason=" << nack.getReason() << "\n";
                NDN_LOG_WARN("Nack uri=" << uri << " reason=" << nack.getReason());
                m_round = 0;
                ++m_queryIdx;
                sendNext();
            },

            // Timeout callback
            [this, uri](const ndn::Interest&) {
                std::cout << "[CON" << m_id << "] TIMEOUT for " << uri << "\n";
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
    std::string     m_id;

    std::vector<Query> m_queries;
    size_t             m_queryIdx = 0;
    int                m_round    = 0;

    std::chrono::steady_clock::time_point m_startTime;
};

int main(int argc, char* argv[])
{
    std::string shareDir   = (argc > 1) ? argv[1] : "/shared";
    std::string namesFile  = (argc > 2) ? argv[2] : "/data/names.txt";
    int         queryCount = (argc > 3) ? std::stoi(argv[3]) : 5;
    std::string consumerId = (argc > 4) ? argv[4] : "?";

    try {
        Consumer consumer(shareDir, namesFile, queryCount, consumerId);
        consumer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
