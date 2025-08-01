#pragma once
#include <vector>
#include <cstdint>

namespace Crypto {
    // Encrypt data with AES-128-CBC. Outputs padded ciphertext.
    std::vector<uint8_t> AES_CBC_Encrypt(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv
    );

    // Decrypt data with AES-128-CBC. Strips padding.
    std::vector<uint8_t> AES_CBC_Decrypt(
        const std::vector<uint8_t>& cipher,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv
    );
}
