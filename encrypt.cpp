#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <regex>
#include <stdexcept>
#include <iomanip>
#include <random>
#include <algorithm>
#include <zip.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/err.h>

// g++ -std=c++17 encrypt.cpp -I"C:\Users\Tristan Ruel\vcpkg\installed\x64-windows\include" -L"C:\Users\Tristan Ruel\vcpkg\installed\x64-windows\lib" -lssl -Wno-deprecated-declarations -lcrypto -lzip -o encryptor

namespace fs = std::filesystem;

struct Settings {
    uintmax_t maxFileSize;
    bool nameEncryption;
};

uintmax_t parseSize(const std::string& sizeStr) {
    std::regex re(R"((\d+)\s*(GB|MB|KB))", std::regex::icase);
    std::smatch match;
    if (std::regex_search(sizeStr, match, re)) {
        uintmax_t number = std::stoull(match[1]);
        std::string unit = match[2];
        if (unit == "GB" || unit == "gb")
            return number * 1024ULL * 1024ULL * 1024ULL;
        else if (unit == "MB" || unit == "mb")
            return number * 1024ULL * 1024ULL;
        else if (unit == "KB" || unit == "kb")
            return number * 1024ULL;
    }
    throw std::runtime_error("Failed to parse size: " + sizeStr);
}

Settings readSettings(const fs::path& settingsFile) {
    Settings settings;
    std::ifstream in(settingsFile);
    if (!in)
        throw std::runtime_error("Cannot open settings file: " + settingsFile.string());
    
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string key;
        if (std::getline(iss, key, '=')) {
            std::string value;
            std::getline(iss, value);
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            if (key == "Max_File_Size")
                settings.maxFileSize = parseSize(value);
            else if (key == "Name_Encryption")
                settings.nameEncryption = (value == "1");
        }
    }
    return settings;
}

bool readDeletionSetting(const fs::path& settingsFile) {
    std::ifstream in(settingsFile);
    if (!in)
        throw std::runtime_error("Cannot open settings file: " + settingsFile.string());
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string key, eq, value;
        if (iss >> key >> eq >> value) {
            if (key == "Deletion_Setting" && value == "1")
                return true;
        }
    }
    return false;
}

std::vector<fs::path> listFiles(const fs::path& dir) {
    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (fs::is_regular_file(entry.path()))
            files.push_back(entry.path());
    }
    return files;
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

std::vector<unsigned char> readFile(const fs::path& filePath) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in)
        throw std::runtime_error("Cannot open file: " + filePath.string());
    return { std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };
}

std::string readTextFile(const fs::path& filePath) {
    std::ifstream in(filePath);
    if (!in)
        throw std::runtime_error("Cannot open file: " + filePath.string());
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

std::string generateRandomString(size_t length) {
    static const char charset[] =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, static_cast<int>(sizeof(charset) - 2));
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i)
        result += charset[dist(gen)];
    return result;
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

std::vector<unsigned char> customAesGcmEncrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    const size_t IV_LEN = 12;
    std::vector<unsigned char> iv(IV_LEN);
    if (RAND_bytes(iv.data(), IV_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)IV_LEN, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed (key/iv)");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen,
                          plaintext.data(), (int)plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    int totalLen = outLen;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + totalLen, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    totalLen += outLen;
    ciphertext.resize(totalLen);

    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> out;
    out.reserve(IV_LEN + tag.size() + ciphertext.size());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

std::vector<unsigned char> customEccEncrypt(
    const std::vector<unsigned char>& data,
    const fs::path& eccPublicKeyFile)
{
    std::string contents = readTextFile(eccPublicKeyFile);
    std::regex re(R"(Public Key\s*\d*\s*:\s*\r?\n\s*([0-9A-Fa-f]+))");
    std::smatch match;
    if (!std::regex_search(contents, match, re)) {
        throw std::runtime_error("Could not find ECC public key in file: " + eccPublicKeyFile.string());
    }
    std::string hexPub = match[1].str();
    std::vector<unsigned char> pubBytes = hexStringToBytes(hexPub);

    EC_KEY* recipientKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!recipientKey)
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    const EC_GROUP* group = EC_KEY_get0_group(recipientKey);
    EC_POINT* pubPoint = EC_POINT_new(group);
    if (!pubPoint) {
        EC_KEY_free(recipientKey);
        throw std::runtime_error("EC_POINT_new failed");
    }
    if (EC_POINT_oct2point(group, pubPoint, pubBytes.data(), pubBytes.size(), nullptr) != 1) {
        EC_POINT_free(pubPoint);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("EC_POINT_oct2point failed");
    }
    if (EC_KEY_set_public_key(recipientKey, pubPoint) != 1) {
        EC_POINT_free(pubPoint);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("EC_KEY_set_public_key failed");
    }
    EC_POINT_free(pubPoint);

    EC_KEY* ephemeralKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ephemeralKey) {
        EC_KEY_free(recipientKey);
        throw std::runtime_error("Failed to create ephemeral EC_KEY");
    }
    if (EC_KEY_generate_key(ephemeralKey) != 1) {
        EC_KEY_free(ephemeralKey);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("Ephemeral EC_KEY generation failed");
    }

    int fieldSize = EC_GROUP_get_degree(EC_KEY_get0_group(ephemeralKey));
    int secretLen = (fieldSize + 7) / 8;
    std::vector<unsigned char> secret(secretLen);
    int outLen = ECDH_compute_key(secret.data(), secretLen,
                                  EC_KEY_get0_public_key(recipientKey),
                                  ephemeralKey, nullptr);
    if (outLen <= 0) {
        EC_KEY_free(ephemeralKey);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("ECDH_compute_key failed");
    }
    secret.resize(outLen);
    if (secret.size() < 32)
        secret.resize(32, 0);
    else if (secret.size() > 32)
        secret.resize(32);

    std::vector<unsigned char> ciphertext = customAesGcmEncrypt(data, secret);

    const EC_GROUP* ephemGroup = EC_KEY_get0_group(ephemeralKey);
    const EC_POINT* ephemPub = EC_KEY_get0_public_key(ephemeralKey);
    unsigned char* buf = nullptr;
    size_t pubSize = EC_POINT_point2buf(ephemGroup, ephemPub, POINT_CONVERSION_UNCOMPRESSED, &buf, nullptr);
    if (buf == nullptr || pubSize == 0) {
        EC_KEY_free(ephemeralKey);
        EC_KEY_free(recipientKey);
        throw std::runtime_error("Failed to encode ephemeral public key");
    }
    std::vector<unsigned char> ephemPubBytes(buf, buf + pubSize);
    OPENSSL_free(buf);

    EC_KEY_free(ephemeralKey);
    EC_KEY_free(recipientKey);

    std::vector<unsigned char> out;
    out.reserve(ephemPubBytes.size() + ciphertext.size());
    out.insert(out.end(), ephemPubBytes.begin(), ephemPubBytes.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

bool createZipFile(const fs::path& zipPath,
                   const std::vector<std::pair<std::string, std::vector<unsigned char>>>& files) {
    int errorp;
    zip_t* archive = zip_open(zipPath.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &errorp);
    if (!archive) {
        std::cerr << "Failed to create zip file: " << zipPath << std::endl;
        return false;
    }
    
    for (const auto& [filename, data] : files) {
        zip_source_t* source = zip_source_buffer(archive, data.data(), data.size(), 0);
        if (!source) {
            std::cerr << "Failed to create zip source for file: " << filename << std::endl;
            zip_close(archive);
            return false;
        }
        if (zip_file_add(archive, filename.c_str(), source, ZIP_FL_ENC_UTF_8) < 0) {
            std::cerr << "Failed to add file to zip: " << filename << std::endl;
            zip_source_free(source);
            zip_close(archive);
            return false;
        }
    }
    
    if (zip_close(archive) < 0) {
        std::cerr << "Failed to close zip file: " << zipPath << std::endl;
        return false;
    }
    return true;
}

void printProgress(int percent, const std::string& message) {
    std::cout << "[" << std::setw(3) << percent << "%] " << message << std::endl;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        printProgress(0, "Reading settings...");
        fs::path settingsFile = fs::path("Settings") / "settings.txt";
        Settings settings = readSettings(settingsFile);
        printProgress(5, "Settings loaded.");

        fs::path importFolder = "Import";
        uintmax_t totalSize = 0;
        std::vector<fs::path> importFiles = listFiles(importFolder);
        for (const auto& file : importFiles)
            totalSize += fs::file_size(file);
        if (totalSize > settings.maxFileSize)
            throw std::runtime_error("Total size of Import folder exceeds maximum allowed file size.");
        printProgress(10, "Import folder size verified.");

        fs::path aesFolder = "AES Keys";
        fs::path latestAESKeyFile = getLatestKeyFile(aesFolder, "AES_key_", ".txt");
        std::string aesKeyText = readTextFile(latestAESKeyFile);
        std::istringstream aesStream(aesKeyText);
        std::string header;
        std::getline(aesStream, header);
        std::string keyHex;
        std::getline(aesStream, keyHex);
        if (keyHex.empty())
            throw std::runtime_error("AES key not found in file: " + latestAESKeyFile.string());
        std::vector<unsigned char> aesKeyBytes = hexStringToBytes(keyHex);
        if (aesKeyBytes.size() != 32)
            throw std::runtime_error("AES key is not 32 bytes (256 bits).");
        printProgress(15, "AES key loaded from " + latestAESKeyFile.string());

        fs::path eccFolder = "ECC Keys";
        fs::path latestECCPublicKeyFile = getLatestKeyFile(eccFolder, "ECC_public_key_", ".txt");
        printProgress(20, "ECC public key file selected: " + latestECCPublicKeyFile.string());

        std::vector<std::pair<std::string, std::vector<unsigned char>>> zipFilesData;
        size_t numFiles = importFiles.size();
        size_t currentFile = 0;
        for (const auto& file : importFiles) {
            currentFile++;
            std::string origFilename = file.filename().string();
            int progressPct = 20 + static_cast<int>(currentFile * 50.0 / (numFiles + 1));
            printProgress(progressPct, "Encrypting file: " + origFilename);
            
            std::vector<unsigned char> plainData = readFile(file);
            std::vector<unsigned char> cipherData = customAesGcmEncrypt(plainData, aesKeyBytes);
            
            std::string outFilename = origFilename;
            if (settings.nameEncryption) {
                std::string extension = fs::path(origFilename).extension().string();
                outFilename = generateRandomString(12) + extension;
            }
            outFilename += ".secure";
            zipFilesData.emplace_back(outFilename, cipherData);
        }
        printProgress(75, "All import files encrypted.");

        std::vector<unsigned char> eccEncryptedAES = customEccEncrypt(aesKeyBytes, latestECCPublicKeyFile);
        std::string aesKeyFilename = latestAESKeyFile.filename().string() + ".secure";
        zipFilesData.emplace_back(aesKeyFilename, eccEncryptedAES);
        printProgress(85, "AES key file encrypted with ECC.");

        fs::create_directories("Export");
        fs::path exportZip = fs::path("Export") / "Export.zip.secure";        
        if (!createZipFile(exportZip, zipFilesData))
            throw std::runtime_error("Failed to create zip file.");
        printProgress(100, "Export zip created: " + exportZip.string());

        std::cout << "Encryption and packaging completed successfully." << std::endl;

        bool deletion = readDeletionSetting(settingsFile);
        if (deletion) {
            fs::remove(latestAESKeyFile);
            printProgress(105, "Deleted AES key file: " + latestAESKeyFile.string());
            fs::remove(latestECCPublicKeyFile);
            printProgress(106, "Deleted ECC public key file: " + latestECCPublicKeyFile.string());
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
