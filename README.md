cat << 'EOF' > readme.md
# Cryptographic Suite

This project comprises a suite of cryptographic key generation tools that utilise the natural radioactive decay of Uranium-238 (U-238) to generate randomness. This method ensures the production of highly secure and unique keys for both AES and ECC encryption systems. The suite contains a collection of C++ and Python tools designed for end-to-end file encryption and decryption using AES and ECC (Elliptic Curve Cryptography), along with utilities for generating high-quality randomness (via Von Neumann extraction) and managing cryptographic keys. A tkinter-based Python GUI (`ui.py`) is also provided to streamline common operations.

---

## Overview

The Cryptographic Suite comprises:

1. **Randomness Generation (Von Neumann extractor)**
   - **`von-neumann-extractor.cpp`** generates unbiased random bits from raw data from the radiation measurements.
   - Produces 256-bit random keys stored as text files in the `Randomness` folder.

2. **ECC Generator**
   - **`ECC-generator.cpp`** creates ECC private/public key pairs using the secp256r1 curve.
   - Writes the keys to the `ECC Keys` folder.

3. **AES Generator**
   - **`AES-generator.cpp`** derives 256-bit AES keys by XORing multiple 256-bit random files from the `Randomness` folder.
   - Outputs keys to the `AES Keys` folder.

4. **Public Key Generator**
   - **`public.cpp`** can take an existing ECC private key and derive its public key component.

5. **Encrypt/Decrypt Utilities**
   - **`encrypt.cpp`** compresses, optionally renames, and encrypts files using AES (for file data) and ECC (to encrypt the AES key).
   - **`decrypt.cpp`** reverses the process, decrypting the AES key with ECC and then the file data with AES.

6. **GUI (`ui.py`)**
   - Python-based TkinterDnD GUI for uploading files, performing encryption/decryption, generating randomness, and toggling settings.

7. **Miscellaneous**
   - **`test_von_neumann_extractor.cpp`** includes a Catch2 test for verifying the Von Neumann extractor logic.
   - **`install.bat`** (Windows batch) for installing or updating dependencies needed by the project (e.g., libraries like OpenSSL, GMP, zip).


## Dependencies

### C++ Requirements (for compiling, not required if just running the .exe files)

- A C++ compiler supporting C++17 or newer.
- **OpenSSL** (for AES, ECC, and cryptographic primitives).
- **libzip** (for creating and reading zip archives).
- **GMP**
- **Catch2** (if you want to compile and run the test file, `test_von_neumann_extractor.cpp`).

### Python Requirements

- **Python 3.7+**
- **TkinterDnD2** (for drag-and-drop file handling).
- **Tkinter** (GUI).
- Possibly other packages depending on your system environment.

### Windows Batch

- **`install.bat`** can help install or update libraries. Adjust its contents as needed for your environment. (Windows only)

---

## Building and Running (C++)

1. **Install necessary libraries**:
   - On Windows, run:
     ```
     install.bat
     ```

2. **Compile (optional, run the .exe files instead)**:
   - For each C++ file, you must link against OpenSSL, GMP, and libzip. Example (Windows):
     ```bash
     g++ -std=c++17 AES-generator.cpp -lgmp -lssl -lcrypto -lzip -o AES-generator
     g++ -std=c++17 ECC-generator.cpp -lgmp -lssl -lcrypto -o ECC-generator
     g++ -std=c++17 encrypt.cpp -lssl -lcrypto -lzip -o encryptor
     g++ -std=c++17 decrypt.cpp -lssl -lcrypto -lzip -o decryptor
     g++ -std=c++17 von-neumann-extractor.cpp -lgmp -o von-neumann-extractor
     g++ -std=c++17 public.cpp -lssl -lcrypto -o public
     g++ -std=c++17 test_von_neumann_extractor.cpp -I<catch2-include> -o test_runner
     ```
     Adjust library include/link paths as necessary.

3. **Run (without GUI)**:
   - **`von-neumann-extractor.exe`**: Takes your raw data from `Radiation Data/...` and outputs multiple 256-bit files in `Randomness`.
   - **`ECC-generator.exe`**: Consumes random files from `Randomness` to generate ECC keypairs in `ECC Keys`.
   - **`public.exe`**: Derives ECC public key from an existing private key.
   - **`AES-generator.exe`**: Consumes random files to generate a 256-bit AES key in `AES Keys`.
   - **`encryptor.exe`**: Encrypts files from `Import` (and outputs to `Export`).
   - **`decryptor.exe`**: Decrypts from `Export` (and outputs to `Decrypted`).

4. **Testing** (optional):
   - **`test_von_neumann_extractor.exe`**: Runs the Catch2 test for Von Neumann extraction.

---

## Running the GUI (`ui.py`)

1. Ensure **Python 3** is installed, plus the required tkinter-based libraries:
   ```
   pip install tkinterdnd2
   ```
2. Launch the GUI by running the `ui.py` script.
   - Use the drag-and-drop interface to upload CSV or Excel files into the “Generate Randomness” panel.
   - Use the menu options to generate randomness, generate ECC or AES keys, encrypt files (from `Import` to `Export`), or decrypt files (from `Export` to `Decrypted`).
   - Adjust settings such as maximum file size and temporary file deletion through the GUI.

---

## Typical Workflow

1. Place your raw data (radiation CSV files) in the `Radiation Data/` folder.
2. Run **`von-neumann-extractor`** (or use the GUI option) to create unbiased 256-bit text files in the `Randomness/` folder.
3. Run **`ECC-generator`** or **`AES-generator`** to produce ECC and AES keys, respectively.
4. Run **`public`** to produce public ECC keys.
4. Place the files or folders you wish to encrypt in the `Import/` folder.
5. Run **`encryptor`** (or use the GUI’s “Encrypt File” option) to create an encrypted archive in the `Export/` folder.
6. To decrypt, run **`decryptor`** (or use the GUI’s “Decrypt File” option) to output the decrypted files in the `Decrypted/` folder.

---

## Notes and Tips

1. **File Size Limits**  
   - The default code is designed for small- to medium-sized files (64GB). Large files may require additional memory and disk space. Configure the maximum file size in the GUI settings or adjust the relevant sections in `encrypt.cpp`.

2. **Security**  
   - Always protect the private keys in `ECC Keys/` and the AES keys in `AES Keys/`.
   - The software is designed to remove or overwrite randomness files after use to minimise reuse. Verify the “Deletion_Setting” in the `Settings/settings.txt` file or via the GUI toggles.

3. **Platform Compatibility**  
   - Windows is the primary target environment. For macOS or Linux, adapt the compilation process (for example, by omitting the `.exe` extension and adjusting library paths) and use shell scripts instead of the provided `.bat` file.

4. **Error Handling**  
   - The application automatically creates missing directories when needed. If you encounter errors opening files, ensure that all required subdirectories are present and correctly named.

5. **Testing**  
   - Compile and run `test_von_neumann_extractor.cpp` with Catch2 to verify the core random extraction logic.
