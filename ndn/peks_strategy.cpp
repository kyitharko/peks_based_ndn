/**
 * @file peks_strategy.cpp
 * @brief PeksStrategy implementation: trapdoor table loading, ExactMatch/LongestMatch search.
 */
#include "peks_strategy.hpp"
#include <nfd/daemon/fw/algorithm.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <fstream>
#include <cstdlib>

NDN_LOG_INIT(peks.strategy);

namespace nfd::fw {

NFD_REGISTER_STRATEGY(PeksStrategy);

const Name& PeksStrategy::getStrategyName()
{
    static const Name name("/localhost/nfd/strategy/peks/%FD%01");
    return name;
}

PeksStrategy::PeksStrategy(Forwarder& forwarder, const Name& name)
    : Strategy(forwarder)
    , m_peks(m_bp)
{
    this->setInstanceName(makeInstanceName(name, getStrategyName()));

    const char* dir = std::getenv("TRAPDOOR_DIR");
    if (dir == nullptr) {
        NDN_LOG_WARN("TRAPDOOR_DIR not set — strategy will reject all Interests");
        return;
    }
    loadTrapdoors(dir);
    NDN_LOG_INFO("Loaded " << m_trapdoorTable.size() << " trapdoor rows from " << dir);
}

// Load 2D trapdoor table from files named td_{row}_{col}.bin.
// Outer loop increments row until td_{row}_0.bin is not found.
// Inner loop increments col until td_{row}_{col}.bin is not found.
void PeksStrategy::loadTrapdoors(const std::string& dir)
{
    m_trapdoorTable.clear();
    for (int row = 0; ; ++row) {
        std::string col0 = dir + "/td_" + std::to_string(row) + "_0.bin";
        if (!std::ifstream(col0))
            break;

        TrapdoorRow trow;
        for (int col = 0; ; ++col) {
            std::string path = dir + "/td_" + std::to_string(row)
                               + "_" + std::to_string(col) + ".bin";
            std::ifstream f(path, std::ios::binary);
            if (!f) break;
            std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(f), {});
            trow.tds.push_back(PeksName::decodeTrapdoor(bytes));
            NDN_LOG_DEBUG("  td_" << row << "_" << col
                          << " (" << bytes.size() << " bytes)");
        }
        NDN_LOG_INFO("Row " << row << ": " << trow.tds.size() << " trapdoors");
        m_trapdoorTable.push_back(std::move(trow));
    }
}

// Algorithm 1 (Ko et al. 2020) — ExactMatch / LongestMatch
//
// Input : Interest name /peks_strategy/C1/.../Ck, trapdoor table, P_pub
// Output: forward on ExactMatch or LongestMatch; reject if no match.
void PeksStrategy::afterReceiveInterest(const Interest& interest,
                                         const FaceEndpoint& ingress,
                                         const shared_ptr<pit::Entry>& pitEntry)
{
    const Name& name = interest.getName();

    // Interest name format: /producer/peks_strategy/C1/.../Ck
    // Component [0] = "producer"       — routing prefix, skip.
    // Component [1] = "peks_strategy"  — PEKS marker, skip.
    // Components [2 .. n-1] are the PEKS ciphertexts (PEKSList in the paper).
    // A name without "peks_strategy" never reaches this strategy because NFD
    // only invokes PeksStrategy for the /producer/peks_strategy prefix.
    const size_t offset = 2;

    if (m_trapdoorTable.empty()) {
        NDN_LOG_WARN("Trapdoor table empty — rejecting: " << name);
        this->rejectPendingInterest(pitEntry);
        return;
    }

    // Build PEKSList from Interest name
    std::vector<PEKS::Ciphertext> peksList;
    for (size_t i = offset; i < name.size(); ++i) {
        try {
            peksList.push_back(PeksName::decodeComponent(name.at(i)));
        }
        catch (const std::exception& e) {
            NDN_LOG_WARN("Cannot decode component[" << i << "]: " << e.what()
                         << " — rejecting");
            this->rejectPendingInterest(pitEntry);
            return;
        }
    }

    if (peksList.empty()) {
        NDN_LOG_WARN("No encrypted components — rejecting: " << name);
        this->rejectPendingInterest(pitEntry);
        return;
    }

    // --- ExactMatch / LongestMatch search (with memoized test results) ---
    //
    // Optimization (Ko et al. 2020): when rows share a common prefix in the
    // trapdoor table, pairing tests for those shared components should not be
    // repeated.  We key each completed test by (column_index, trapdoor_bytes)
    // and cache the bool result.  On a cache hit we skip the pairing entirely.
    //
    // Example:
    //   Row 0: [tw11, tw12, tw13]   test(C1,tw11)✓ → cached; test(C2,tw12)✗
    //   Row 1: [tw11, tw21, tw23]   test(C1,tw11) → cache HIT ✓, skip pairing
    //                                test(C2,tw21) → new test
    //   Row 2: [tw11, tw12, tw31]   test(C1,tw11) → cache HIT ✓
    //                                test(C2,tw12) → cache HIT ✓, skip pairing
    //                                test(C3,tw31) → new test
    //
    // Cache key: column index concatenated with serialised trapdoor bytes.
    // Using std::string as the key type to support unordered_map directly.

    // Build cache key: 8-byte little-endian column index + raw trapdoor bytes
    auto makeCacheKey = [](size_t col, const PEKS::Trapdoor& td) -> std::string {
        uint8_t colBytes[8];
        size_t  tmp = col;
        for (int b = 0; b < 8; ++b, tmp >>= 8) colBytes[b] = static_cast<uint8_t>(tmp);
        std::vector<uint8_t> tdBytes = PeksName::encodeTrapdoor(td);
        std::string key(reinterpret_cast<char*>(colBytes), 8);
        key.append(reinterpret_cast<char*>(tdBytes.data()), tdBytes.size());
        return key;
    };

    std::unordered_map<std::string, bool> testCache;
    size_t cacheHits = 0, newTests = 0;

    auto cachedTest = [&](size_t col,
                          const PEKS::Ciphertext& ct,
                          const PEKS::Trapdoor&   td) -> bool {
        std::string key = makeCacheKey(col, td);
        auto it = testCache.find(key);
        if (it != testCache.end()) {
            ++cacheHits;
            NDN_LOG_DEBUG("cache HIT col=" << col << " → " << it->second);
            return it->second;
        }
        bool result = m_peks.test(ct, td);
        testCache[key] = result;
        ++newTests;
        return result;
    };

    int  bestRow        = -1;
    int  bestMatchCount =  0;
    bool exactMatch     = false;

    for (size_t row = 0; row < m_trapdoorTable.size(); ++row) {
        const auto& tds = m_trapdoorTable[row].tds;
        if (tds.empty()) continue;

        // Line 7: test first component — uses cache if this trapdoor was seen before
        if (!cachedTest(0, peksList[0], tds[0])) continue;

        // First component matched; continue testing remaining columns
        int    matchCount = 1;
        size_t col        = 1;

        while (col < tds.size() && col < peksList.size()) {
            if (!cachedTest(col, peksList[col], tds[col])) break;
            ++matchCount;
            ++col;
        }

        // ExactMatch — all row columns consumed AND same length as Interest
        if (matchCount == static_cast<int>(tds.size()) &&
            peksList.size() == tds.size()) {
            exactMatch = true;
            bestRow    = static_cast<int>(row);
            NDN_LOG_INFO("ExactMatch row=" << row
                         << " components=" << matchCount
                         << " pairings=" << newTests
                         << " cacheHits=" << cacheHits
                         << " — forwarding: " << name);
            break;
        }

        // LongestMatch — best partial match so far
        if (matchCount > bestMatchCount) {
            bestMatchCount = matchCount;
            bestRow        = static_cast<int>(row);
            NDN_LOG_DEBUG("LongestMatch candidate row=" << row
                          << " matchCount=" << matchCount);
        }
    }

    NDN_LOG_INFO("Search done: pairings=" << newTests
                 << " cacheHits=" << cacheHits
                 << " rows=" << m_trapdoorTable.size());

    // Line 29: return tmp (bestRow) — reject if nothing matched at all
    if (bestRow < 0) {
        NDN_LOG_INFO("No match — rejecting: " << name);
        this->rejectPendingInterest(pitEntry);
        return;
    }

    if (!exactMatch) {
        NDN_LOG_INFO("LongestMatch row=" << bestRow
                     << " (" << bestMatchCount << " components) — forwarding: " << name);
    }

    // Forward on best eligible next hop
    const auto& fib = this->lookupFib(*pitEntry);
    for (const auto& nexthop : fib.getNextHops()) {
        if (isNextHopEligible(ingress.face, interest, nexthop, pitEntry)) {
            this->sendInterest(interest, nexthop.getFace(), pitEntry);
            return;
        }
    }

    NDN_LOG_WARN("No eligible next hop for row=" << bestRow << " — rejecting");
    this->rejectPendingInterest(pitEntry);
}

} // namespace nfd::fw
