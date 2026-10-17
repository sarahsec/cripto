#include "crypto.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

static int failures = 0;

static void expect(bool ok, const char* name) {
    if (!ok) {
        std::cerr << "FAIL " << name << '\n';
        ++failures;
    }
}

int main() {
    expect(encryptCaesar("Abc", 1) == "Bcd", "caesar encrypt");
    expect(decryptCaesar("Bcd", 1) == "Abc", "caesar decrypt");

    const ByteVector original{0xde, 0xad, 0xbe, 0xef};
    expect(fromHex(toHex(original)).value() == original, "hex roundtrip");
    expect(!fromHex("abc").has_value(), "odd hex rejected");
    expect(fromHex(" ab cd ").value() == ByteVector({0xab, 0xcd}), "hex ignores spaces");

    const ByteVector message = stringToBytes("hi");
    const ByteVector key = stringToBytes("xy");
    auto cipher = otpTransform(message, key);
    expect(cipher.has_value(), "otp encrypt");
    auto plain = otpTransform(cipher.value(), key);
    expect(plain.has_value() && bytesToString(plain.value()) == "hi", "otp decrypt");

    ByteVector reuseKey(8, 0x11);
    auto c1 = otpTransform(ByteVector(8, 'A'), reuseKey);
    auto c2 = otpTransform(ByteVector(8, 'B'), reuseKey);
    auto leak = otpTransform(c1.value(), c2.value());
    ByteVector expectedXor(8, static_cast<unsigned char>('A' ^ 'B'));
    expect(leak.has_value() && leak.value() == expectedXor, "otp reuse cancels key");

    auto sealed = aesGcmEncrypt("lab");
    expect(sealed.has_value(), "aes encrypt");
    auto opened = aesGcmDecrypt(sealed.value());
    expect(opened.has_value() && opened.value() == "lab", "aes decrypt");

    auto empty = aesGcmEncrypt("");
    expect(empty.has_value(), "aes empty encrypt");
    AesGcmBundle tampered = empty.value();
    expect(tamperAesBundle(tampered), "aes empty tamper flips tag");
    expect(!aesGcmDecrypt(tampered).has_value(), "aes empty tamper rejects");

    auto hexBack = fromHex(toHex(sealed->key));
    expect(hexBack.has_value() && hexBack.value() == sealed->key, "aes key hex");

    if (failures != 0) {
        std::cerr << failures << " failed\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
