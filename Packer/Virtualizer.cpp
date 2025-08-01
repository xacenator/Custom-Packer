// src/Virtualizer.cpp
#include "Virtualizer.h"

namespace Virtualizer {
    void VirtualizeSections(LIEF::PE::Binary* /*bin*/) {
        // no-op until VM engine is implemented
    }

    std::vector<uint8_t> GetLoaderStub(
        const std::vector<uint8_t>& /*key*/,
        const std::vector<uint8_t>& /*iv*/,
        uint32_t /*origEP*/
    ) {
        return {};  // empty stub for now
    }
}
