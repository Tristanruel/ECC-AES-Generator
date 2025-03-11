#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <regex>
#include <stdexcept>
#include <iomanip>
#include <memory>
#include <zip.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/err.h>

namespace fs = std::filesystem;
//g++ -std=c++17 decrypt.cpp -I"C:\Users\Tristan Ruel\vcpkg\installed\x64-windows\include" -L"C:\Users\Tristan Ruel\vcpkg\installed\x64-windows\lib" -lssl -Wno-deprecated-declarations -lcrypto -lzip -o decryptor

void printProgress(int percent, const std::string& message) {
    std::cout << "[" << std::setw(3) << percent << "%] " << message << std::endl;
}

std::string readTextFile(const fs::path& filePath) {
    std::ifstream in(filePath);
    if (!in)
        throw std::runtime_error("Cannot open file: " + filePath.string());
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

std::vector<unsigned char> hexStringToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::runtime_error("Invalid hex string length.");
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned val = std::stoul(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(static_cast<unsigned char>(val));
    }
    return bytes;
}

fs::path getLatestKeyFile(const fs::path& folder, const std::string& prefix, const std::string& suffix) {
    fs::path latestFile;
    int maxIndex = -1;
    std::regex re(prefix + R"((\d+))" + suffix);
    
    for (const auto& entry : fs::directory_iterator(folder)) {
        if (!fs::is_regular_file(entry.path()))
            continue;
        std::smatch match;
        std::string filename = entry.path().filename().string();
        if (std::regex_match(filename, match, re)) {
            int index = std::stoi(match[1]);
            if (index > maxIndex) {
                maxIndex = index;
                latestFile = entry.path();
            }
        }
    }
    if (maxIndex == -1)
        throw std::runtime_error("No valid key file found in folder: " + folder.string());
    return latestFile;
}

bool readDeletionSetting(const fs::path& settingsFile) {
    std::ifstream in(settingsFile);
    if (!in)
        throw std::runtime_error("Cannot open settings file: " + settingsFile.string());
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string key, equals, value;
        if (iss >> key >> equals >> value) {
            if (key == "Deletion_Setting" && value == "1")
                return true;
        }
    }
    return false;
}

std::vector<unsigned char> customAesGcmDecrypt(
    const std::vector<unsigned char>& encrypted,
    const std::vector<unsigned char>& key)
{
    const size_t IV_LEN = 12;
    const size_t TAG_LEN = 16;
    if (encrypted.size() < IV_LEN + TAG_LEN)
        throw std::runtime_error("Encrypted data too short.");

    std::vector<unsigned char> iv(encrypted.begin(), encrypted.begin() + IV_LEN);
    std::vector<unsigned char> tag(encrypted.begin() + IV_LEN, encrypted.begin() + IV_LEN + TAG_LEN);
    std::vector<unsigned char> ciphertext(encrypted.begin() + IV_LEN + TAG_LEN, encrypted.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)IV_LEN, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length");
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed (key/iv)");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int outLen = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext.data(), (int)ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    int totalLen = outLen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM tag");
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed (possibly due to tag mismatch)");
    }
    totalLen += outLen;
    plaintext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::vector<unsigned char> customEccDecrypt(
    const std::vector<unsigned char>& encryptedData,
    const fs::path& eccPrivateKeyFile)
{
    const size_t ephemeralPubKeyLen = 65;
    if (encryptedData.size() < ephemeralPubKeyLen)
        throw std::runtime_error("Invalid ECC encrypted data.");

    std::vector<unsigned char> ephemeralPubBytes(encryptedData.begin(), encryptedData.begin() + ephemeralPubKeyLen);
    std::vector<unsigned char> aesEncryptedData(encryptedData.begin() + ephemeralPubKeyLen, encryptedData.end());

    std::string contents = readTextFile(eccPrivateKeyFile);
    std::regex re(R"(.*Private Key.*:\s*\r?\n\s*([0-9A-Fa-f]+))");
    std::smatch match;
    if (!std::regex_search(contents, match, re))
        throw std::runtime_error("Could not find ECC private key in file: " + eccPrivateKeyFile.string());
    std::string hexPriv = match[1].str();
    std::vector<unsigned char> privBytes = hexStringToBytes(hexPriv);

    EC_KEY* recipientKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!recipientKey)
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    BIGNUM* privBN = BN_bin2bn(privBytes.data(), privBytes.size(), nullptr);
    if (!privBN) {
        EC_KEY_free(recipientKey);
        throw std::runtime_error("BN_bin2bn failed");
    }
    if (EC_KEY_set_private_key(recipientKey, privBN) != 1) {
        BN_free(privBN);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("EC_KEY_set_private_key failed");
    }
    BN_free(privBN);

    const EC_GROUP* group = EC_KEY_get0_group(recipientKey);
    EC_POINT* ephemeralPubPoint = EC_POINT_new(group);
    if (!ephemeralPubPoint) {
        EC_KEY_free(recipientKey);
        throw std::runtime_error("EC_POINT_new failed");
    }
    if (EC_POINT_oct2point(group, ephemeralPubPoint, ephemeralPubBytes.data(), ephemeralPubBytes.size(), nullptr) != 1) {
        EC_POINT_free(ephemeralPubPoint);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("EC_POINT_oct2point failed");
    }

    int fieldSize = EC_GROUP_get_degree(group);
    int secretLen = (fieldSize + 7) / 8;
    std::vector<unsigned char> secret(secretLen);
    int outLen = ECDH_compute_key(secret.data(), secretLen, ephemeralPubPoint, recipientKey, nullptr);
    if (outLen <= 0) {
        EC_POINT_free(ephemeralPubPoint);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("ECDH_compute_key failed");
    }
    secret.resize(outLen);
    if (secret.size() < 32)
        secret.resize(32, 0);
    else if (secret.size() > 32)
        secret.resize(32);

    EC_POINT_free(ephemeralPubPoint);
    EC_KEY_free(recipientKey);

    std::vector<unsigned char> aesKey = customAesGcmDecrypt(aesEncryptedData, secret);
    return aesKey;
}

std::vector<std::pair<std::string, std::vector<unsigned char>>> readZipFile(const fs::path& zipPath) {
    int errorp;
    zip_t* archive = zip_open(zipPath.string().c_str(), ZIP_RDONLY, &errorp);
    if (!archive)
        throw std::runtime_error("Failed to open zip file: " + zipPath.string());

    std::vector<std::pair<std::string, std::vector<unsigned char>>> files;
    zip_int64_t numEntries = zip_get_num_entries(archive, 0);
    for (zip_uint64_t i = 0; i < (zip_uint64_t)numEntries; ++i) {
        zip_stat_t st;
        if (zip_stat_index(archive, i, 0, &st) != 0)
            continue;
        std::string filename = st.name;
        zip_file_t* zf = zip_fopen_index(archive, i, 0);
        if (!zf)
            continue;
        std::vector<unsigned char> buffer(st.size);
        zip_int64_t n = zip_fread(zf, buffer.data(), st.size);
        if (n < 0) {
            zip_fclose(zf);
            zip_close(archive);
            throw std::runtime_error("Error reading file: " + filename);
        }
        zip_fclose(zf);
        files.emplace_back(filename, std::move(buffer));
    }
    zip_close(archive);
    return files;
}


void writeFile(const fs::path& filePath, const std::vector<unsigned char>& data) {
    std::ofstream out(filePath, std::ios::binary);
    if (!out)
        throw std::runtime_error("Failed to open output file: " + filePath.string());
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    fs::path eccFolder = "ECC Keys";
    fs::path eccPrivateKeyFile = getLatestKeyFile(eccFolder, "ECC_key_pair_", ".txt");

    fs::path zipFile = fs::path("Export") / "Export.zip.secure";

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        printProgress(0, "Using ECC private key file: " + eccPrivateKeyFile.string());
        printProgress(5, "Opening zip file: " + zipFile.string());
        auto zipEntries = readZipFile(zipFile);
        printProgress(10, "Read " + std::to_string(zipEntries.size()) + " zip entries.");

        std::vector<unsigned char> aesKey;
        bool foundAesKey = false;
        printProgress(15, "Identifying AES key file...");
        for (const auto& [filename, data] : zipEntries) {
            if (filename.find("AES_key_") != std::string::npos) {
                printProgress(20, "Decrypting AES key from file: " + filename);
                aesKey = customEccDecrypt(data, eccPrivateKeyFile);
                foundAesKey = true;
                break;
            }
        }
        if (!foundAesKey)
            throw std::runtime_error("AES key file not found in the zip archive.");
        printProgress(25, "AES key decrypted.");

        printProgress(30, "Creating output folder 'Decrypted'...");
        fs::path outputFolder = "Decrypted";
        fs::create_directories(outputFolder);

        std::vector<std::pair<std::string, std::vector<unsigned char>>> dataFiles;
        for (const auto& entry : zipEntries) {
            if (entry.first.find("AES_key_") == std::string::npos)
                dataFiles.push_back(entry);
        }

        size_t numFiles = dataFiles.size();
        size_t currentFile = 0;
        for (const auto& [filename, data] : dataFiles) {
            currentFile++;
            int progressPct = 35 + static_cast<int>((currentFile * (90 - 35)) / (numFiles + 1));
            printProgress(progressPct, "Decrypting file: " + filename);
            std::vector<unsigned char> plainData = customAesGcmDecrypt(data, aesKey);
            fs::path outName = filename;
            if (outName.extension() == ".secure")
                outName.replace_extension("");
            fs::path outPath = outputFolder / outName.filename();
            writeFile(outPath, plainData);
            printProgress(progressPct, "Decrypted file written to: " + outPath.string());
        }

        fs::path movedZip = outputFolder / zipFile.filename();
        fs::rename(zipFile, movedZip);
        printProgress(95, "Moved " + zipFile.string() + " to " + movedZip.string());

        fs::path settingsFile = "Settings/settings.txt";
        bool deletion = readDeletionSetting(settingsFile);
        if (deletion) {
            fs::remove(movedZip);
            printProgress(98, "Deleted " + movedZip.string());
            fs::remove(eccPrivateKeyFile);
            printProgress(99, "Deleted ECC private key file: " + eccPrivateKeyFile.string());
        }
        
        printProgress(100, "Decryption completed successfully.");
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << std::endl;
        EVP_cleanup();
        ERR_free_strings();
        return EXIT_FAILURE;
    }

    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
