#include "Crypto.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>
#include <string>

namespace Crypto {

    static void throw_if_zero(int ok) {
        if (!ok) {
            unsigned long err = ERR_get_error();
            throw std::runtime_error("OpenSSL error: " + std::to_string(err));
        }
    }

    std::vector<uint8_t> AES_CBC_Encrypt(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv
    ) {
        if (key.size() != 16 || iv.size() != 16)
            throw std::runtime_error("Key/IV must be 16 bytes");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        // 1. Init
        throw_if_zero(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()));

        // 2. Provide data
        std::vector<uint8_t> out;
        out.resize(data.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
        int len1 = 0;
        throw_if_zero(EVP_EncryptUpdate(ctx, out.data(), &len1, data.data(), (int)data.size()));

        // 3. Finalize (handles padding)
        int len2 = 0;
        throw_if_zero(EVP_EncryptFinal_ex(ctx, out.data() + len1, &len2));

        out.resize(len1 + len2);
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    std::vector<uint8_t> AES_CBC_Decrypt(
        const std::vector<uint8_t>& cipher,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv
    ) {
        if (key.size() != 16 || iv.size() != 16)
            throw std::runtime_error("Key/IV must be 16 bytes");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        throw_if_zero(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()));

        std::vector<uint8_t> out;
        out.resize(cipher.size());
        int len1 = 0;
        throw_if_zero(EVP_DecryptUpdate(ctx, out.data(), &len1, cipher.data(), (int)cipher.size()));

        int len2 = 0;
        throw_if_zero(EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2));

        out.resize(len1 + len2);
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

}  // namespace Crypto
