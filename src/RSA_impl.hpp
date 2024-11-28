#ifndef RSA_IMPL_H
#define RSA_IMPL_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <vector>

#include "error_handler.h"
#include "settings.h"

namespace RSA_impl {
    struct RSA_Keychain {
        RSA* keychain = nullptr;
        RSA* publicKey = nullptr;
        RSA* privateKey = nullptr;

        ~RSA_Keychain() {
            RSA_free(keychain);
            RSA_free(publicKey);
            RSA_free(privateKey);
        }

        static RSA_Keychain Generate(const int keySize) {
            RSA* rsa = RSA_new();
            BIGNUM* bn = BN_new();
            if (!BN_set_word(bn, RSA_F4)) // RSA_F4 is a common public exponent (65537)
                handleErrors();

            if (!RSA_generate_key_ex(rsa, keySize, bn, nullptr))
                handleErrors();

            BN_free(bn);
            return { rsa, RSAPublicKey_dup(rsa), RSAPrivateKey_dup(rsa) };
        }
    };

    std::vector<unsigned char> Encrypt(RSA* publicKey, const std::string& plaintext) {
        std::vector<unsigned char> ciphertext(RSA_size(publicKey));
        int result = RSA_public_encrypt(
            plaintext.size(),
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            ciphertext.data(),
            publicKey,
            RSA_PKCS1_OAEP_PADDING // Use OAEP padding for security
        );

        if (result == -1) {
            handleErrors();
        }

        return ciphertext;
    }

    std::string Decrypt(RSA* privateKey, const std::vector<unsigned char>& ciphertext) {
        std::vector<unsigned char> plaintext(RSA_size(privateKey));
        int result = RSA_private_decrypt(
            ciphertext.size(),
            ciphertext.data(),
            plaintext.data(),
            privateKey,
            RSA_PKCS1_OAEP_PADDING // Use OAEP padding for security
        );

        if (result == -1) {
            handleErrors();
        }

        // Resize to actual plaintext size and convert to string
        return std::string(plaintext.begin(), plaintext.begin() + result);
    }
}

#endif