#pragma once

#include <optional>
#include <string>
#include <vector>

using ByteVector = std::vector<unsigned char>;

struct AesGcmBundle {
    ByteVector key;
    ByteVector iv;
    ByteVector ciphertext;
    ByteVector tag;
};

std::string toHex(const ByteVector& data);
std::optional<ByteVector> fromHex(const std::string& hex);
ByteVector stringToBytes(const std::string& input);
std::string bytesToString(const ByteVector& bytes);
std::string encryptCaesar(const std::string& text, int shift);
std::string decryptCaesar(const std::string& text, int shift);
std::optional<ByteVector> otpTransform(const ByteVector& input, const ByteVector& key);
bool randomBytes(ByteVector& output);
std::optional<AesGcmBundle> aesGcmEncrypt(const std::string& plaintext);
std::optional<std::string> aesGcmDecrypt(const AesGcmBundle& bundle);
bool tamperAesBundle(AesGcmBundle& bundle);
