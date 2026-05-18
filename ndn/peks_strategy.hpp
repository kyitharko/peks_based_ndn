#pragma once
#include "../peks.hpp"
#include "peks_name.hpp"
#include <nfd/daemon/fw/strategy.hpp>
#include <vector>
#include <unordered_map>
#include <string>

namespace nfd::fw {

// PeksStrategy — NFD forwarding strategy implementing the PEKS-based NDN
// name-privacy scheme from Ko et al. (Future Internet 2020, 12(8), 130).
//
// Interest name format: /peks_strategy/C1/C2/.../Ck
//   where Ci = PEKS(P_pub, N_i) and N_i is the i-th plaintext name component.
//
// The router holds a 2D trapdoor table: each row is one registered data name,
// each column is the trapdoor for one component of that name.
//
// Matching algorithm (Algorithm 1, Ko et al. 2020):
//   ExactMatch  — all components in a row match AND row length == Interest length
//   LongestMatch — the row with the most consecutive matching components from [0]
//
// Trapdoors are loaded at startup from TRAPDOOR_DIR (files: td_{row}_{col}.bin).
// A sentinel file td_ready.flag signals that the full table has been written.
class PeksStrategy : public Strategy {
public:
    explicit PeksStrategy(Forwarder& forwarder,
                          const Name& name = getStrategyName());

    static const Name& getStrategyName();

    void afterReceiveInterest(const Interest& interest,
                              const FaceEndpoint& ingress,
                              const shared_ptr<pit::Entry>& pitEntry) override;

private:
    struct TrapdoorRow {
        std::vector<PEKS::Trapdoor> tds;  // one trapdoor per name component
    };

    void loadTrapdoors(const std::string& dir);

    AtePairing                m_bp;
    PEKS                      m_peks;
    std::vector<TrapdoorRow>  m_trapdoorTable;  // [row][col]
};

} // namespace nfd::fw
