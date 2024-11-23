# Cryptographic Key Generation Suite

This project comprises a suite of cryptographic key generation tools using various algorithms and methods. The suite includes AES key generation, ECC key generation, and a randomness extractor based on von Neumann's method.

## Modules

### AES Key Generator (`AES-generator.cpp`)

Generates a 256-bit AES key by XORing binary codes from selected randomness files, which are then deleted to ensure each key is used only once. The keys are then stored in the `AES Keys` directory.

### ECC Key Generator (`ECC-generator.cpp`)

Generates elliptic curve cryptography (ECC) key pairs based on the secp256r1 curve. It selects two binary code files from the `Randomness` directory, computes ECC keys, and outputs them into the `ECC Keys` directory. Each key generation results in one private key and a corresponding public key.

### Von Neumann Extractor (`von-neumann-extractor.cpp`)

Processes a CSV file containing counts per second from the decay of U-238 to extract randomness using von Neumann's debiasing method. The randomness extracted is then outputted as files containing unbiased binary sequences ready to be used by other modules in the suite.

