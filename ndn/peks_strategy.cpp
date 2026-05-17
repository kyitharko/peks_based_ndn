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
    NDN_LOG_INFO("Loaded " << m_trapdoors.size() << " trapdoors from " << dir);
}

void PeksStrategy::loadTrapdoors(const std::string& dir)
{
    for (int i = 0; ; ++i) {
        std::string path = dir + "/td_" + std::to_string(i) + ".bin";
        std::ifstream f(path, std::ios::binary);
        if (!f)
            break;
        std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(f), {});
        m_trapdoors.push_back(PeksName::decodeTrapdoor(bytes));
        NDN_LOG_DEBUG("Loaded trapdoor " << i << " (" << bytes.size() << " bytes)");
    }
}

void PeksStrategy::afterReceiveInterest(const Interest& interest,
                                         const FaceEndpoint& ingress,
                                         const shared_ptr<pit::Entry>& pitEntry)
{
    const Name& name = interest.getName();

    // Component [0] is the plaintext routing prefix "peks" — skip it.
    // Components [1 .. m_trapdoors.size()] are the PEKS ciphertexts.
    const size_t offset = 1;

    if (m_trapdoors.empty()) {
        NDN_LOG_WARN("No trapdoors loaded — rejecting: " << name);
        this->rejectPendingInterest(pitEntry);
        return;
    }

    if (name.size() < offset + m_trapdoors.size()) {
        NDN_LOG_WARN("Name too short (" << name.size() << " components) — rejecting");
        this->rejectPendingInterest(pitEntry);
        return;
    }

    // Run PEKS::test() for each encrypted component
    for (size_t i = 0; i < m_trapdoors.size(); ++i) {
        PEKS::Ciphertext c;
        try {
            c = PeksName::decodeComponent(name.at(offset + i));
        }
        catch (const std::exception& e) {
            NDN_LOG_WARN("Failed to decode component[" << (offset + i) << "]: " << e.what());
            this->rejectPendingInterest(pitEntry);
            return;
        }

        if (!m_peks.test(c, m_trapdoors[i])) {
            NDN_LOG_INFO("Component[" << (offset + i) << "] failed PEKS test — rejecting");
            this->rejectPendingInterest(pitEntry);
            return;
        }
    }

    NDN_LOG_INFO("All " << m_trapdoors.size() << " components matched — forwarding: " << name);

    // Forward on the best eligible next hop
    const auto& fib = this->lookupFib(*pitEntry);
    for (const auto& nexthop : fib.getNextHops()) {
        if (isNextHopEligible(ingress.face, interest, nexthop, pitEntry)) {
            this->sendInterest(pitEntry, nexthop.getFace(), interest);
            return;
        }
    }

    NDN_LOG_WARN("No eligible next hop — rejecting");
    this->rejectPendingInterest(pitEntry);
}

} // namespace nfd::fw
