#pragma once
#include "../peks.hpp"
#include "peks_name.hpp"
#include <nfd/daemon/fw/strategy.hpp>
#include <vector>
#include <unordered_map>
#include <string>

/**
 * @file peks_strategy.hpp
 * @brief NFD forwarding strategy implementing the PEKS-based NDN name-privacy scheme.
 */

namespace nfd::fw {

/**
 * @class PeksStrategy
 * @brief NFD forwarding strategy that runs the PEKS ExactMatch / LongestMatch
 *        search (Algorithm 1, Ko et al. 2020) on every incoming Interest.
 *
 * ### Strategy name
 * `/localhost/nfd/strategy/peks/%FD%01`
 *
 * Registered in NFD with:
 * @code{.sh}
 * nfdc strategy set /producer/peks_strategy /localhost/nfd/strategy/peks/%FD%01
 * @endcode
 *
 * Only Interests whose name begins with `/producer/peks_strategy` are dispatched
 * to this strategy.  Interests for bare `/producer` continue to use BestRoute.
 *
 * ### Interest name format
 * @code
 * /producer / peks_strategy / C1 / C2 / ... / Ck
 *      │            │          └──────────────────┘
 *      routing   PEKS marker   PEKS ciphertexts
 *      prefix                  (one per plaintext component)
 * @endcode
 * Components `[0]` (`producer`) and `[1]` (`peks_strategy`) are skipped;
 * components `[2 .. n-1]` are decoded as PEKS::Ciphertext values.
 *
 * ### Trapdoor table
 * The 2D table is loaded at startup from files `td_{row}_{col}.bin` in the
 * directory pointed to by the `TRAPDOOR_DIR` environment variable.
 * Row = registered URI index; column = component position within that URI.
 *
 * ### Matching algorithm
 * For each row `r` in the table:
 * 1. Test `(C[0], td[r][0])` — skip row on mismatch.
 * 2. Continue testing `(C[j], td[r][j])` for `j = 1, 2, …`
 * 3. **ExactMatch** — row length equals Interest length and all tests pass →
 *    forward immediately.
 * 4. **LongestMatch** — record row with the most consecutive matches from
 *    component 0, forward after scanning all rows.
 * 5. **No match** — reject the Interest (NACK).
 *
 * ### Memoised pairing tests
 * An Ate pairing on BLS12-381 costs ~1 ms.  When multiple rows share a
 * common prefix in the trapdoor table the same `(column, trapdoor)` pair
 * appears in several rows.  Results are cached in a per-Interest
 * `std::unordered_map` keyed by `(8-byte column index) ‖ (48-byte G1 bytes)`.
 * On a cache hit the pairing is skipped entirely.
 *
 * The router logs the cache statistics per Interest:
 * @code
 * Search done: pairings=6 cacheHits=12 rows=103
 * @endcode
 *
 * @see PeksName for the wire encoding used to decode Interest components.
 * @see PEKS::test() for the pairing computation.
 */
class PeksStrategy : public Strategy {
public:
    /**
     * @brief Construct and load the trapdoor table.
     *
     * Reads `TRAPDOOR_DIR` from the environment and calls loadTrapdoors().
     * If the environment variable is unset, the strategy logs a warning and
     * rejects all Interests.
     *
     * @param forwarder NFD Forwarder instance (passed by NFD on strategy creation).
     * @param name      Strategy name (default: getStrategyName()).
     */
    explicit PeksStrategy(Forwarder& forwarder,
                          const Name& name = getStrategyName());

    /**
     * @brief Return the canonical strategy name.
     * @return `/localhost/nfd/strategy/peks/%FD%01`
     */
    static const Name& getStrategyName();

    /**
     * @brief Entry point for every Interest that matches the strategy prefix.
     *
     * Decodes PEKS ciphertexts from the Interest name, runs the
     * ExactMatch / LongestMatch search, then either forwards or rejects.
     *
     * @param interest  Incoming Interest.
     * @param ingress   Face and endpoint the Interest arrived on.
     * @param pitEntry  PIT entry for this Interest.
     */
    void afterReceiveInterest(const Interest& interest,
                              const FaceEndpoint& ingress,
                              const shared_ptr<pit::Entry>& pitEntry) override;

private:
    /** @brief One row of the trapdoor table — one trapdoor per URI component. */
    struct TrapdoorRow {
        std::vector<PEKS::Trapdoor> tds; ///< Ordered trapdoors: `tds[col]` for component `col`.
    };

    /**
     * @brief Load the 2D trapdoor table from binary files in @p dir.
     *
     * Iterates rows `0, 1, 2, …` until `td_{row}_0.bin` is not found.
     * For each row iterates columns until `td_{row}_{col}.bin` is not found.
     *
     * @param dir Directory containing `td_{row}_{col}.bin` files.
     */
    void loadTrapdoors(const std::string& dir);

    AtePairing               m_bp;             ///< BLS12-381 pairing context.
    PEKS                     m_peks;            ///< PEKS instance (test only; no keygen/encrypt).
    std::vector<TrapdoorRow> m_trapdoorTable;  ///< Loaded trapdoor table [row][col].
};

} // namespace nfd::fw
