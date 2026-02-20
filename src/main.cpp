#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace {

using ByteVector = std::vector<unsigned char>;

std::string toHex(const ByteVector& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::string encryptCaesar(const std::string& text, int shift) {
    std::string result = text;
    const int normalizedShift = ((shift % 26) + 26) % 26;

    for (char& ch : result) {
        if (std::isupper(static_cast<unsigned char>(ch))) {
            ch = static_cast<char>('A' + (ch - 'A' + normalizedShift) % 26);
        } else if (std::islower(static_cast<unsigned char>(ch))) {
            ch = static_cast<char>('a' + (ch - 'a' + normalizedShift) % 26);
        }
    }

    return result;
}

std::string decryptCaesar(const std::string& text, int shift) {
    return encryptCaesar(text, -shift);
}

void bruteForceCaesar(const std::string& ciphertext) {
    std::cout << "\nPossible plaintexts:\n";
    for (int shift = 0; shift < 26; ++shift) {
        std::cout << "Shift " << std::setw(2) << shift << ": "
                  << decryptCaesar(ciphertext, shift) << '\n';
    }
}

ByteVector stringToBytes(const std::string& input) {
    return ByteVector(input.begin(), input.end());
}

std::string bytesToString(const ByteVector& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

std::optional<ByteVector> otpTransform(const ByteVector& input, const ByteVector& key) {
    if (input.size() != key.size()) {
        return std::nullopt;
    }

    ByteVector output(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i];
    }
    return output;
}

bool randomBytes(ByteVector& output) {
    return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}

struct AesGcmBundle {
    ByteVector key;
    ByteVector iv;
    ByteVector ciphertext;
    ByteVector tag;
};

std::optional<AesGcmBundle> aesGcmEncrypt(const std::string& plaintext) {
    EVP_CIPHER_CTX* rawCtx = EVP_CIPHER_CTX_new();
    if (rawCtx == nullptr) {
        return std::nullopt;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(rawCtx, EVP_CIPHER_CTX_free);

    AesGcmBundle bundle;
    bundle.key.resize(32);
    bundle.iv.resize(12);
    bundle.tag.resize(16);
    bundle.ciphertext.resize(plaintext.size());

    if (!randomBytes(bundle.key) || !randomBytes(bundle.iv)) {
        return std::nullopt;
    }

    int outLen = 0;
    int totalLen = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return std::nullopt;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(bundle.iv.size()), nullptr) != 1) {
        return std::nullopt;
    }

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, bundle.key.data(), bundle.iv.data()) != 1) {
        return std::nullopt;
    }

    if (EVP_EncryptUpdate(ctx.get(), bundle.ciphertext.data(), &outLen,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        return std::nullopt;
    }
    totalLen = outLen;

    if (EVP_EncryptFinal_ex(ctx.get(), bundle.ciphertext.data() + totalLen, &outLen) != 1) {
        return std::nullopt;
    }
    totalLen += outLen;
    bundle.ciphertext.resize(totalLen);

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(bundle.tag.size()), bundle.tag.data()) != 1) {
        return std::nullopt;
    }

    return bundle;
}

std::optional<std::string> aesGcmDecrypt(const AesGcmBundle& bundle) {
    EVP_CIPHER_CTX* rawCtx = EVP_CIPHER_CTX_new();
    if (rawCtx == nullptr) {
        return std::nullopt;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(rawCtx, EVP_CIPHER_CTX_free);

    ByteVector plaintext(bundle.ciphertext.size());
    int outLen = 0;
    int totalLen = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return std::nullopt;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(bundle.iv.size()), nullptr) != 1) {
        return std::nullopt;
    }

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, bundle.key.data(), bundle.iv.data()) != 1) {
        return std::nullopt;
    }

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen, bundle.ciphertext.data(), static_cast<int>(bundle.ciphertext.size())) != 1) {
        return std::nullopt;
    }
    totalLen = outLen;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(bundle.tag.size()), const_cast<unsigned char*>(bundle.tag.data())) != 1) {
        return std::nullopt;
    }

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + totalLen, &outLen) != 1) {
        return std::nullopt;
    }
    totalLen += outLen;
    plaintext.resize(totalLen);

    return bytesToString(plaintext);
}

void runCaesar() {
    std::string plaintext;
    int shift = 0;

    std::cout << "Plaintext: ";
    std::getline(std::cin, plaintext);
    std::cout << "Shift (integer): ";
    std::cin >> shift;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    const std::string encrypted = encryptCaesar(plaintext, shift);
    const std::string decrypted = decryptCaesar(encrypted, shift);

    std::cout << "Encrypted: " << encrypted << '\n';
    std::cout << "Decrypted: " << decrypted << '\n';

    bruteForceCaesar(encrypted);
}

void runOtp() {
    std::string plaintext;
    std::cout << "Plaintext: ";
    std::getline(std::cin, plaintext);

    std::cout << "Choose key mode:\n";
    std::cout << "1) Manual key (same length as plaintext)\n";
    std::cout << "2) Generate random key\n";
    std::cout << "Selection: ";

    int mode = 0;
    std::cin >> mode;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    ByteVector messageBytes = stringToBytes(plaintext);
    ByteVector key;

    if (mode == 1) {
        std::string keyInput;
        std::cout << "Key (text, exactly " << messageBytes.size() << " chars): ";
        std::getline(std::cin, keyInput);
        key = stringToBytes(keyInput);
    } else if (mode == 2) {
        key.resize(messageBytes.size());
        if (!randomBytes(key)) {
            std::cout << "Failed to generate secure random key.\n";
            return;
        }
    } else {
        std::cout << "Invalid selection.\n";
        return;
    }

    auto encrypted = otpTransform(messageBytes, key);
    if (!encrypted.has_value()) {
        std::cout << "OTP error: key length must exactly match plaintext length.\n";
        return;
    }

    auto decrypted = otpTransform(encrypted.value(), key);
    if (!decrypted.has_value()) {
        std::cout << "Unexpected OTP error during decryption.\n";
        return;
    }

    std::cout << "Key (hex):        " << toHex(key) << '\n';
    std::cout << "Ciphertext (hex): " << toHex(encrypted.value()) << '\n';
    std::cout << "Decrypted text:   " << bytesToString(decrypted.value()) << '\n';
}

void runAesGcm() {
    std::string plaintext;
    std::cout << "Plaintext: ";
    std::getline(std::cin, plaintext);

    auto encrypted = aesGcmEncrypt(plaintext);
    if (!encrypted.has_value()) {
        std::cout << "AES-GCM encryption failed.\n";
        return;
    }

    std::cout << "Key (hex):        " << toHex(encrypted->key) << '\n';
    std::cout << "IV (hex):         " << toHex(encrypted->iv) << '\n';
    std::cout << "Ciphertext (hex): " << toHex(encrypted->ciphertext) << '\n';
    std::cout << "Tag (hex):        " << toHex(encrypted->tag) << '\n';

    auto decrypted = aesGcmDecrypt(encrypted.value());
    if (!decrypted.has_value()) {
        std::cout << "AES-GCM decryption failed (authentication error).\n";
        return;
    }

    std::cout << "Decrypted text:   " << decrypted.value() << '\n';

    AesGcmBundle tampered = encrypted.value();
    if (!tampered.ciphertext.empty()) {
        tampered.ciphertext[0] ^= 0x01;
    }

    auto tamperedResult = aesGcmDecrypt(tampered);
    std::cout << "Tamper test:      "
              << (tamperedResult.has_value() ? "unexpectedly succeeded" : "decryption rejected (expected)")
              << '\n';
}

void printMenu() {
    std::cout << "\n=== Cryptography Lab CLI ===\n";
    std::cout << "1) Caesar Cipher (breakable)\n";
    std::cout << "2) One-Time Pad (theoretically unbreakable, impractical)\n";
    std::cout << "3) AES-256-GCM (modern recommended)\n";
    std::cout << "0) Exit\n";
    std::cout << "Selection: ";
}

}  // namespace

int main() {
    while (true) {
        printMenu();

        int selection = -1;
        std::cin >> selection;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (selection) {
            case 1:
                runCaesar();
                break;
            case 2:
                runOtp();
                break;
            case 3:
                runAesGcm();
                break;
            case 0:
                std::cout << "Goodbye!\n";
                return 0;
            default:
                std::cout << "Invalid option. Try again.\n";
                break;
        }
    }
}
