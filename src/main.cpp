#include "crypto.hpp"

#include <iomanip>
#include <iostream>
#include <limits>
#include <string>

namespace {

bool readInt(int& value) {
    if (std::cin >> value) {
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return true;
    }
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return false;
}

void bruteForceCaesar(const std::string& ciphertext) {
    std::cout << "\nPossible plaintexts:\n";
    for (int shift = 0; shift < 26; ++shift) {
        std::cout << "Shift " << std::setw(2) << shift << ": "
                  << decryptCaesar(ciphertext, shift) << '\n';
    }
}

void runCaesar() {
    std::string plaintext;
    int shift = 0;

    std::cout << "Plaintext: ";
    std::getline(std::cin, plaintext);
    std::cout << "Shift (integer): ";
    if (!readInt(shift)) {
        std::cout << "Invalid shift.\n";
        return;
    }

    const std::string encrypted = encryptCaesar(plaintext, shift);
    const std::string decrypted = decryptCaesar(encrypted, shift);

    std::cout << "Encrypted: " << encrypted << '\n';
    std::cout << "Decrypted: " << decrypted << '\n';

    bruteForceCaesar(encrypted);
}

void demonstrateOtpKeyReuse(const ByteVector& key) {
    if (key.empty()) {
        return;
    }

    ByteVector first = stringToBytes("ATTACK AT DAWN");
    ByteVector second = stringToBytes("ATTACK AT DUSK");
    first.resize(key.size(), static_cast<unsigned char>(' '));
    second.resize(key.size(), static_cast<unsigned char>(' '));

    auto cipher1 = otpTransform(first, key);
    auto cipher2 = otpTransform(second, key);
    if (!cipher1.has_value() || !cipher2.has_value()) {
        return;
    }

    auto leak = otpTransform(cipher1.value(), cipher2.value());
    if (!leak.has_value()) {
        return;
    }

    ByteVector expected(key.size());
    for (size_t i = 0; i < key.size(); ++i) {
        expected[i] = first[i] ^ second[i];
    }

    std::cout << "\nKey reuse (same key on two messages):\n";
    std::cout << "C1 xor C2 (hex):  " << toHex(leak.value()) << '\n';
    std::cout << "M1 xor M2 (hex):  " << toHex(expected) << '\n';
    std::cout << "C1 xor C2 equals M1 xor M2. the key cancelled out.\n";
}

std::optional<ByteVector> readHex(const std::string& label) {
    std::string line;
    std::cout << label;
    std::getline(std::cin, line);
    return fromHex(line);
}

void decryptOtpFromHex() {
    auto ciphertext = readHex("Ciphertext (hex): ");
    auto key = readHex("Key (hex): ");
    if (!ciphertext.has_value() || !key.has_value()) {
        std::cout << "Invalid hex.\n";
        return;
    }
    auto decrypted = otpTransform(ciphertext.value(), key.value());
    if (!decrypted.has_value()) {
        std::cout << "OTP error: key length must exactly match ciphertext length.\n";
        return;
    }
    std::cout << "Decrypted text:   " << bytesToString(decrypted.value()) << '\n';
}

void decryptAesFromHex() {
    auto key = readHex("Key (hex): ");
    auto iv = readHex("IV (hex): ");
    auto ciphertext = readHex("Ciphertext (hex): ");
    auto tag = readHex("Tag (hex): ");
    if (!key.has_value() || !iv.has_value() || !ciphertext.has_value() || !tag.has_value()) {
        std::cout << "Invalid hex.\n";
        return;
    }
    AesGcmBundle bundle;
    bundle.key = std::move(key.value());
    bundle.iv = std::move(iv.value());
    bundle.ciphertext = std::move(ciphertext.value());
    bundle.tag = std::move(tag.value());
    auto decrypted = aesGcmDecrypt(bundle);
    if (!decrypted.has_value()) {
        std::cout << "AES-GCM decryption failed (authentication error).\n";
        return;
    }
    std::cout << "Decrypted text:   " << decrypted.value() << '\n';
}

void runOtp() {
    std::cout << "1) Encrypt\n";
    std::cout << "2) Decrypt from hex\n";
    std::cout << "Selection: ";
    int action = 0;
    if (!readInt(action)) {
        std::cout << "Invalid selection.\n";
        return;
    }
    if (action == 2) {
        decryptOtpFromHex();
        return;
    }
    if (action != 1) {
        std::cout << "Invalid selection.\n";
        return;
    }

    std::string plaintext;
    std::cout << "Plaintext: ";
    std::getline(std::cin, plaintext);

    std::cout << "Choose key mode:\n";
    std::cout << "1) Manual key (same length as plaintext)\n";
    std::cout << "2) Generate random key\n";
    std::cout << "Selection: ";

    int mode = 0;
    if (!readInt(mode)) {
        std::cout << "Invalid selection.\n";
        return;
    }

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
    demonstrateOtpKeyReuse(key);
}

void runAesGcm() {
    std::cout << "1) Encrypt\n";
    std::cout << "2) Decrypt from hex\n";
    std::cout << "Selection: ";
    int action = 0;
    if (!readInt(action)) {
        std::cout << "Invalid selection.\n";
        return;
    }
    if (action == 2) {
        decryptAesFromHex();
        return;
    }
    if (action != 1) {
        std::cout << "Invalid selection.\n";
        return;
    }

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
    if (!tamperAesBundle(tampered)) {
        std::cout << "Tamper test:      skipped (nothing to flip)\n";
        return;
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
        if (!readInt(selection)) {
            std::cout << "Invalid option. Try again.\n";
            continue;
        }

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
