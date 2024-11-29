#ifndef AES_IMPL_H
#define AES_IMPL_H

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string>
#include "error_handler.h"

namespace AES_impl {
    struct Cfg {
        std::vector<unsigned char> key;
        std::vector<unsigned char> iv;

        static Cfg Generate(const int keySize) {
            // Generate a random 2048-bit key (512 bytes)
            std::vector<unsigned char> key(keySize / 4);
            if (!RAND_bytes(key.data(), key.size())) {
                handleErrors();
            }

            // Generate a random 128-bit IV (16 bytes)
            std::vector<unsigned char> iv(16);
            if (!RAND_bytes(iv.data(), iv.size())) {
                handleErrors();
            }

            return { key, iv };
        }
    };

    std::vector<unsigned char> encrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        // Initialize encryption context
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
            handleErrors();
        }

        // Encrypt the plaintext
        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int len = 0, ciphertext_len = 0;

        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size())) {
            handleErrors();
        }
        ciphertext_len = len;

        // Finalize encryption
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
            handleErrors();
        }
        ciphertext_len += len;

        // Clean up
        EVP_CIPHER_CTX_free(ctx);

        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }


    std::string decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        // Initialize decryption context
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
            handleErrors();
        }

        // Decrypt the ciphertext
        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0, plaintext_len = 0;

        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
            handleErrors();
        }
        plaintext_len = len;

        // Finalize decryption
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
            handleErrors();
        }
        plaintext_len += len;

        // Clean up
        EVP_CIPHER_CTX_free(ctx);

        plaintext.resize(plaintext_len);
        return std::string(plaintext.begin(), plaintext.end());
    }
}

#endif
