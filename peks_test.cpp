#include "peks.hpp"
#include <cstdio>

int main()
{
    AtePairing bp;
    PEKS peks(bp);

    auto [pk, sk] = peks.keygen();

    printf("=== PEKS on BLS12-381 ===\n\n");

    // Correct keyword matches
    {
        printf("-- Correct keyword --\n");
        for (const char* kw : {"confidential", "alice", "/ndn/home"}) {
            PEKS::Ciphertext c  = peks.encrypt(pk, kw);
            PEKS::Trapdoor   td = peks.trapdoor(sk, kw);
            printf("  encrypt+trapdoor('%s'): %s\n", kw, peks.test(c, td) ? "MATCH" : "FAIL");
        }
    }

    // Wrong keyword must not match
    {
        printf("\n-- Wrong keyword --\n");
        PEKS::Ciphertext c  = peks.encrypt(pk,  "confidential");
        PEKS::Trapdoor   td = peks.trapdoor(sk, "public");
        printf("  encrypt('confidential') vs trapdoor('public'): %s\n",
               !peks.test(c, td) ? "NO MATCH (correct)" : "FAIL (false positive)");
    }

    // Same ciphertext, fresh trapdoor — must still match
    {
        printf("\n-- Ciphertext reuse --\n");
        PEKS::Ciphertext c  = peks.encrypt(pk,  "reuse-kw");
        PEKS::Trapdoor   td = peks.trapdoor(sk, "reuse-kw");
        printf("  same keyword, fresh trapdoor: %s\n", peks.test(c, td) ? "MATCH" : "FAIL");
    }

    // NDN name component search
    {
        printf("\n-- NDN name component search (/ndn/home/alice/data/file1.txt) --\n");
        std::vector<std::string> components = {"ndn", "home", "alice", "data", "file1.txt"};
        std::vector<PEKS::Ciphertext> enc;
        for (const auto& comp : components)
            enc.push_back(peks.encrypt(pk, comp));

        for (const char* query : {"alice", "bob", "data"}) {
            PEKS::Trapdoor td = peks.trapdoor(sk, query);
            printf("  trapdoor('%s'):", query);
            for (size_t i = 0; i < components.size(); ++i)
                if (peks.test(enc[i], td))
                    printf(" found at [%zu]='%s'", i, components[i].c_str());
            printf("\n");
        }
    }

    return 0;
}
