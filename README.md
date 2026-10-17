# cripto

C++ CLI for an academic cryptography lab with three algorithms:

- **Caesar cipher** (breakable)
- **One-Time Pad (OTP)** (unbreakable in theory, impractical in common use)
- **AES-256-GCM** (modern and recommended)

## Requirements

- CMake 3.16+
- C++17 compiler
- OpenSSL (libcrypto)

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

## Run

```bash
./build/cripto
```

## Features

- Interactive menu to pick an algorithm
- Encrypt and decrypt, including pasting hex later
- Hex output for binary data
- OTP demo of what happens if the same key is reused
- AES-GCM tamper test (authentication fails after modification)

---

# cripto (português)

CLI em C++ para laboratório acadêmico de criptografia com três algoritmos:

- **Cifra de César** (quebrável)
- **One-Time Pad (OTP)** (inquebrável em teoria, impraticável no uso comum)
- **AES-256-GCM** (moderno e recomendado)

## Requisitos

- CMake 3.16+
- Compilador C++17
- OpenSSL (libcrypto)

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

## Executar

```bash
./build/cripto
```

## Funcionalidades

- Menu interativo para escolher algoritmo
- Criptografia e descriptografia, inclusive colar hex depois
- Saída em hexadecimal para dados binários
- OTP mostra o que acontece se a mesma chave for reusada
- Teste de violação em AES-GCM (autenticação falha após adulteração)
