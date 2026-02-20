# cripto

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
```

## Executar

```bash
./build/cripto
```

## Funcionalidades

- Menu interativo para escolher algoritmo
- Criptografia e descriptografia para cada algoritmo
- Saída em hexadecimal para dados binários
- Teste de violação em AES-GCM (autenticação falha após adulteração)
