#include "AES_impl.hpp"
#include "ECC_impl.hpp"
#include "RSA_impl.hpp"

#include <fstream>
#include <sstream>

static void PerformBenchmarks(const std::string& plaintext, int keySize, const std::string& outputFilename) {
    std::ofstream output(outputFilename, std::ios::app);
    if (!output.is_open()) {
        std::cout << "Failed to open output file " << outputFilename << std::endl;
        return;
    }

    // === AES ===
    output << keySize << " AES: ";
    auto start = std::chrono::system_clock::now();
    AES_impl::Cfg aes_cfg = AES_impl::Cfg::Generate(keySize);
    auto end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us ";

    // Encrypt the message
    start = std::chrono::system_clock::now();
    std::vector<unsigned char> ciphertext = AES_impl::encrypt(plaintext, aes_cfg.key, aes_cfg.iv);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us ";

    // Output ciphertext in hexadecimal
    std::cout << "AES Ciphertext (hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }
    std::cout << std::endl;

    // Output decrypted plaintext
    start = std::chrono::system_clock::now();
    std::string decrypted = AES_impl::decrypt(ciphertext, aes_cfg.key, aes_cfg.iv);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us\n";

    std::cout << "AES Decrypted Plaintext: " << decrypted << std::endl;

    // === RSA ===
    output << keySize << " RSA: ";
    // Generate RSA key pair
    start = std::chrono::system_clock::now();
    RSA_impl::RSA_Keychain rsa_keychain = RSA_impl::RSA_Keychain::Generate(keySize);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us ";

    start = std::chrono::system_clock::now();
    ciphertext = RSA_impl::Encrypt(rsa_keychain.publicKey, plaintext);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us ";

    // Print ciphertext in hexadecimal
    std::cout << "RSA Ciphertext (hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }
    std::cout << std::endl;

    // Decrypt the message using the private key
    start = std::chrono::system_clock::now();
    decrypted = RSA_impl::Decrypt(rsa_keychain.privateKey, ciphertext);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us\n";
    std::cout << "RSA Decrypted Plaintext: " << decrypted << std::endl;

    // === ECC ===
    output << keySize << " ECC: ";
    start = std::chrono::system_clock::now();
    ECC_impl::ECC_Keychain ecc_keychain_a = ECC_impl::ECC_Keychain::Generate(keySize);
    ECC_impl::ECC_Keychain ecc_keychain_b = ECC_impl::ECC_Keychain::Generate(keySize);
    auto sharedSecretA = ECC_impl::deriveSharedSecret(ecc_keychain_a.keychain, ecc_keychain_b.keychain);
    auto sharedSecretB = ECC_impl::deriveSharedSecret(ecc_keychain_b.keychain, ecc_keychain_a.keychain);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us ";

    // Encrypt the message
    start = std::chrono::system_clock::now();
    ciphertext = ECC_impl::Encrypt(sharedSecretA, plaintext);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us ";

    std::cout << "Ciphertext (hex): ";
    for (unsigned char byte : ciphertext) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    start = std::chrono::system_clock::now();
    decrypted = ECC_impl::Decrypt(sharedSecretB, ciphertext);
    end = std::chrono::system_clock::now();
    output << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us\n\n";

    std::cout << "ECC Decrypted Plaintext: " << decrypted << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc > 0 && argc != 3) {
        std::cout << "Usage: " << argv[0] << " <file_to_encrypt> <key_size>" <<  std::endl;
        return 0;
    }

    std::string fileToEncrypt, plaintext;
    int keySize;

    if (argc == 0) {
        // Reading message to encrypt
        std::cout << "File to encrypt: ";
        std::getline(std::cin, fileToEncrypt);

        // Reading key size
        std::cout << "Key size: ";
        std::cin >> keySize;
    } else if (argc == 3) {
        fileToEncrypt = argv[1];
        keySize = atoi(argv[2]);
    }

    // Loading file
    std::ifstream fin(fileToEncrypt, std::ios::in | std::ios::binary);
    std::ostringstream oss;
    oss << fin.rdbuf();
    plaintext = oss.str();

    // Running benchmarks
    PerformBenchmarks(plaintext, keySize, "benchmarks.txt");

    return 0;
}
