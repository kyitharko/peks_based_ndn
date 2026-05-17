#include "peks_name.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <fstream>
#include <iostream>

NDN_LOG_INIT(peks.consumer);

// Must match the components the producer registered trapdoors for
static const std::vector<std::string> NAME_COMPONENTS = {
    "ndn", "home", "alice", "data", "file1"
};

static const std::string ROUTING_PREFIX = "/peks";

class Consumer {
public:
    explicit Consumer(const std::string& shareDir)
        : m_shareDir(shareDir)
        , m_peks(m_bp)
    {
        // Load producer's public key from shared volume
        std::ifstream f(shareDir + "/pk.bin", std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open " + shareDir + "/pk.bin");
        std::vector<uint8_t> pkBytes(std::istreambuf_iterator<char>(f), {});
        m_pk = PeksName::decodePublicKey(pkBytes);
        NDN_LOG_INFO("Public key loaded (" << pkBytes.size() << " bytes)");
    }

    void run()
    {
        // Build encrypted name: /peks/enc(ndn)/enc(home)/enc(alice)/enc(data)/enc(file1)
        ndn::Name name(ROUTING_PREFIX);
        name.append(PeksName::buildEncryptedSuffix(m_peks, m_pk, NAME_COMPONENTS));

        NDN_LOG_INFO("Sending Interest with " << name.size()
                     << " components (1 plain + "
                     << NAME_COMPONENTS.size() << " encrypted)");

        ndn::Interest interest(name);
        interest.setMustBeFresh(true);
        interest.setInterestLifetime(ndn::time::seconds(8));

        m_face.expressInterest(
            interest,
            [](const ndn::Interest&, const ndn::Data& data) {
                std::string content(
                    reinterpret_cast<const char*>(data.getContent().value()),
                    data.getContent().value_size());
                std::cout << "\n[CONSUMER] Data received: " << content << "\n" << std::endl;
                NDN_LOG_INFO("Data received: " << content);
            },
            [](const ndn::Interest& i, const ndn::lp::Nack& nack) {
                NDN_LOG_WARN("Nack received for " << i.getName()
                             << " reason=" << nack.getReason());
            },
            [](const ndn::Interest& i) {
                NDN_LOG_WARN("Interest timed out: " << i.getName());
                std::cout << "[CONSUMER] Timeout — no Data received." << std::endl;
            });

        m_face.processEvents(ndn::time::seconds(10));
    }

private:
    AtePairing      m_bp;
    PEKS            m_peks;
    PEKS::PublicKey m_pk;
    ndn::Face       m_face;
    std::string     m_shareDir;
};

int main(int argc, char* argv[])
{
    std::string shareDir = (argc > 1) ? argv[1] : "/shared";
    try {
        Consumer consumer(shareDir);
        consumer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
