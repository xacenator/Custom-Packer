
#pragma once
#include <vector>
#include <cstdint>
#include <LIEF/PE.hpp>

namespace Virtualizer {
    void VirtualizeSections(LIEF::PE::Binary* bin);

    // returns the raw bytes of your in-memory loader stub
    std::vector<uint8_t> GetLoaderStub(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        uint32_t originalEP
    );
}
