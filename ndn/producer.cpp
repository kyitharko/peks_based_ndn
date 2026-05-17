#include "peks_name.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <fstream>
#include <iostream>

NDN_LOG_INIT(peks.producer);

// NDN name components the producer owns (plaintext).
// These map 1-to-1 with the trapdoors it distributes to routers.
static const std::vector<std::string> NAME_COMPONENTS = {
    "ndn", "home", "alice", "data", "file1"
};

static const std::string ROUTING_PREFIX = "/peks";

static void saveFile(const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot write " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    NDN_LOG_INFO("Wrote " << data.size() << " bytes → " << path);
}

class Producer {
public:
    explicit Producer(const std::string& shareDir)
        : m_shareDir(shareDir)
        , m_peks(m_bp)
    {
        // 1. Key generation
        auto [pk, sk] = m_peks.keygen();
        m_pk = pk;
        m_sk = sk;

        // 2. Persist public key for consumer
        saveFile(shareDir + "/pk.bin", PeksName::encodePublicKey(m_pk));

        // 3. Generate and persist one trapdoor per name component for router
        for (size_t i = 0; i < NAME_COMPONENTS.size(); ++i) {
            auto td = m_peks.trapdoor(m_sk, NAME_COMPONENTS[i]);
            saveFile(shareDir + "/td_" + std::to_string(i) + ".bin",
                     PeksName::encodeTrapdoor(td));
        }

        NDN_LOG_INFO("Keys and " << NAME_COMPONENTS.size()
                     << " trapdoors written to " << shareDir);
    }

    void run()
    {
        // Register prefix /peks — the router will forward matching Interests here
        m_face.setInterestFilter(
            ndn::InterestFilter(ROUTING_PREFIX),
            [this](const ndn::InterestFilter&, const ndn::Interest& interest) {
                onInterest(interest);
            },
            [](const ndn::Name& prefix, const std::string& reason) {
                NDN_LOG_ERROR("Prefix registration failed for " << prefix
                              << ": " << reason);
            });

        NDN_LOG_INFO("Producer listening on " << ROUTING_PREFIX);
        m_face.processEvents();
    }

private:
    void onInterest(const ndn::Interest& interest)
    {
        NDN_LOG_INFO("Interest received: " << interest.getName());

        ndn::Data data(interest.getName());
        std::string payload = "Hello from PEKS-NDN Producer! (Ko et al. 2020)";
        data.setContent(ndn::make_span(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));
        data.setFreshnessPeriod(ndn::time::seconds(10));
        m_keyChain.sign(data);

        m_face.put(data);
        NDN_LOG_INFO("Data sent: " << data.getName());
    }

    AtePairing      m_bp;
    PEKS            m_peks;
    PEKS::PublicKey m_pk;
    PEKS::SecretKey m_sk;
    ndn::Face       m_face;
    ndn::KeyChain   m_keyChain;
    std::string     m_shareDir;
};

int main(int argc, char* argv[])
{
    std::string shareDir = (argc > 1) ? argv[1] : "/shared";
    try {
        Producer producer(shareDir);
        producer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
