#ifndef ECC_IMPL_H
#define ECC_IMPL_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>

namespace ECC_impl {
    struct ECC_Keychain {
        EVP_PKEY* keychain = nullptr;
        EC_KEY* publicKey = nullptr;

        ~ECC_Keychain() {
            EVP_PKEY_free(keychain);
            EC_KEY_free(publicKey);
        }

        static ECC_Keychain Generate(int keySize) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (!ctx) handleErrors();

            // Initialize ECC key generation (P-256 curve) (256 bits key)
            if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, keySize <= 1024 ? NID_X9_62_prime256v1 : (keySize <= 2048 ? NID_secp384r1 : NID_secp521r1)) <= 0)
                handleErrors(); // P-256 curve

            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors();

            EVP_PKEY_CTX_free(ctx);

            return { pkey, EVP_PKEY_get1_EC_KEY(pkey) };
        }
    };

    static std::vector<unsigned char> deriveSharedSecret(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx) handleErrors();

        if (EVP_PKEY_derive_init(ctx) <= 0) handleErrors();
        if (EVP_PKEY_derive_set_peer(ctx, peerPublicKey) <= 0) handleErrors();

        size_t secretLen;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLen) <= 0) handleErrors();

        std::vector<unsigned char> sharedSecret(secretLen);
        if (EVP_PKEY_derive(ctx, sharedSecret.data(), &secretLen) <= 0) handleErrors();

        EVP_PKEY_CTX_free(ctx);
        return sharedSecret;
    }

    // Encrypting a message using the shared secret (symmetric encryption)
    static std::vector<unsigned char> Encrypt(const std::vector<unsigned char>& sharedSecret, const std::string& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        // AES-256 encryption using the shared secret as the key
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, sharedSecret.data(), nullptr) <= 0) handleErrors();

        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int len = 0, ciphertextLen = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
            handleErrors();
        }
        ciphertextLen = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) <= 0) {
            handleErrors();
        }
        ciphertextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        ciphertext.resize(ciphertextLen);
        return ciphertext;
    }

    // Decrypting the message using the shared secret (symmetric decryption)
    static std::string Decrypt(const std::vector<unsigned char>& sharedSecret, const std::vector<unsigned char>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        // AES-256 decryption using the shared secret as the key
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, sharedSecret.data(), nullptr) <= 0) handleErrors();

        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0, plaintextLen = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) <= 0) {
            handleErrors();
        }
        plaintextLen = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
            handleErrors();
        }
        plaintextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        plaintext.resize(plaintextLen);
        return std::string(plaintext.begin(), plaintext.end());
    }
}

#endif