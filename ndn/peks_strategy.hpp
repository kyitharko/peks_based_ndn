#pragma once
#include "../peks.hpp"
#include "peks_name.hpp"
#include <nfd/daemon/fw/strategy.hpp>
#include <vector>

namespace nfd::fw {

// PeksStrategy — NFD forwarding strategy implementing the PEKS-based NDN
// name-privacy scheme from Ko et al. (Future Internet 2020, 12(8), 130).
//
// On each incoming Interest the strategy decodes the PEKS ciphertexts from
// name components [1..n] and runs PEKS::test() against pre-loaded trapdoors.
// All components must match for the Interest to be forwarded; otherwise it is
// rejected (NACK / dropped at this hop).
//
// Trapdoors are loaded at startup from the directory pointed to by the
// TRAPDOOR_DIR environment variable (files: td_0.bin, td_1.bin, ...).
class PeksStrategy : public Strategy {
public:
    explicit PeksStrategy(Forwarder& forwarder,
                          const Name& name = getStrategyName());

    static const Name& getStrategyName();

    void afterReceiveInterest(const Interest& interest,
                              const FaceEndpoint& ingress,
                              const shared_ptr<pit::Entry>& pitEntry) override;

private:
    void loadTrapdoors(const std::string& dir);

    AtePairing               m_bp;
    PEKS                     m_peks;
    std::vector<PEKS::Trapdoor> m_trapdoors;   // td_0, td_1, ... in order
};

} // namespace nfd::fw
