#include "crypto.hpp"

#include <cctype>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/rand.h>

std::string toHex(const ByteVector& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

static int hexNibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

std::optional<ByteVector> fromHex(const std::string& hex) {
    std::string cleaned;
    cleaned.reserve(hex.size());
    for (unsigned char ch : hex) {
        if (std::isspace(ch)) {
            continue;
        }
        cleaned.push_back(static_cast<char>(ch));
    }
    if (cleaned.size() % 2 != 0) {
        return std::nullopt;
    }
    ByteVector out;
    out.reserve(cleaned.size() / 2);
    for (size_t i = 0; i < cleaned.size(); i += 2) {
        const int high = hexNibble(cleaned[i]);
        const int low = hexNibble(cleaned[i + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<unsigned char>((high << 4) | low));
    }
    return out;
}

ByteVector stringToBytes(const std::string& input) {
    return ByteVector(input.begin(), input.end());
}

std::string bytesToString(const ByteVector& bytes) {
    return std::string(bytes.begin(), bytes.end());
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
    if (output.empty()) {
        return true;
    }
    if (output.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}

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
    bundle.ciphertext.resize(static_cast<size_t>(totalLen));

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

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen, bundle.ciphertext.data(),
                          static_cast<int>(bundle.ciphertext.size())) != 1) {
        return std::nullopt;
    }
    totalLen = outLen;

    ByteVector tag = bundle.tag;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        return std::nullopt;
    }

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + totalLen, &outLen) != 1) {
        return std::nullopt;
    }
    totalLen += outLen;
    plaintext.resize(static_cast<size_t>(totalLen));

    return bytesToString(plaintext);
}

bool tamperAesBundle(AesGcmBundle& bundle) {
    if (!bundle.ciphertext.empty()) {
        bundle.ciphertext[0] ^= 0x01;
        return true;
    }
    if (!bundle.tag.empty()) {
        bundle.tag[0] ^= 0x01;
        return true;
    }
    return false;
}
