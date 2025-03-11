#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
// g++ -std=c++17 public.cpp -o ecc_convert -lssl -lcrypto
// g++ -std=c++17 public.cpp -I"C:\Users\Tristan Ruel\vcpkg\installed\x64-windows\include" -L"C:\Users\Tristan Ruel\vcpkg\installed\x64-windows\lib" -lssl -lcrypto -Wno-deprecated-declarations -o public



namespace fs = std::filesystem;


std::string generatePublicKey(const std::string &privateHex) {
    BIGNUM *priv_bn = nullptr;
    if (BN_hex2bn(&priv_bn, privateHex.c_str()) == 0) {
        std::cerr << "Error converting private key hex to BIGNUM." << std::endl;
        return "";
    }

    int nid = NID_X9_62_prime256v1;
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) {
        std::cerr << "Error creating EC_KEY object." << std::endl;
        BN_free(priv_bn);
        return "";
    }

    if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
        std::cerr << "Error setting the private key." << std::endl;
        EC_KEY_free(ec_key);
        BN_free(priv_bn);
        return "";
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_key = EC_POINT_new(group);
    if (!pub_key) {
        std::cerr << "Error creating EC_POINT for public key." << std::endl;
        EC_KEY_free(ec_key);
        BN_free(priv_bn);
        return "";
    }

    if (EC_POINT_mul(group, pub_key, priv_bn, nullptr, nullptr, nullptr) != 1) {
        std::cerr << "Error computing the public key." << std::endl;
        EC_POINT_free(pub_key);
        EC_KEY_free(ec_key);
        BN_free(priv_bn);
        return "";
    }

    if (EC_KEY_set_public_key(ec_key, pub_key) != 1) {
        std::cerr << "Error setting the computed public key." << std::endl;
        EC_POINT_free(pub_key);
        EC_KEY_free(ec_key);
        BN_free(priv_bn);
        return "";
    }

    char *pub_hex = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::string publicHex;
    if (pub_hex) {
        publicHex = pub_hex;
        OPENSSL_free(pub_hex);
    } else {
        std::cerr << "Error converting public key to hex." << std::endl;
    }

    EC_POINT_free(pub_key);
    EC_KEY_free(ec_key);
    BN_free(priv_bn);

    return publicHex;
}

int main() {
    std::string folder = "ECC Keys";
    std::regex filePattern("ECC_key_pair_(\\d+)\\.txt");
    int maxNumber = -1;
    fs::path selectedFile;

    try {
        for (const auto &entry : fs::directory_iterator(folder)) {
            std::string filename = entry.path().filename().string();
            std::smatch match;
            if (std::regex_match(filename, match, filePattern)) {
                int num = std::stoi(match[1].str());
                if (num > maxNumber) {
                    maxNumber = num;
                    selectedFile = entry.path();
                }
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "Error iterating directory: " << e.what() << std::endl;
        return 1;
    }

    if (maxNumber == -1) {
        std::cerr << "No ECC private key file found in " << folder << std::endl;
        return 1;
    }

    std::ifstream infile(selectedFile);
    if (!infile) {
        std::cerr << "Failed to open file " << selectedFile << std::endl;
        return 1;
    }

    std::vector<std::pair<std::string, std::string>> keys;
    std::string line;
    std::string currentLabel;
    while (std::getline(infile, line)) {
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        if (line.empty() || line.find("----") != std::string::npos)
            continue;

        if (line.find("PrivateKey") != std::string::npos || line.find("PrivateKey:") != std::string::npos ||
            line.find("(PrivateKey):") != std::string::npos ||
            line.find("(PrivateKey)") != std::string::npos ||
            line.find("PrivateKey") != std::string::npos) {
            currentLabel = line;
        } else {
            if (line.size() == 64) {
                keys.push_back({currentLabel, line});
            }
        }
    }
    infile.close();

    if (keys.empty()) {
        std::cerr << "No valid private keys found in file " << selectedFile << std::endl;
        return 1;
    }

    std::ostringstream oss;
    int keyIndex = 1;
    for (const auto &entry : keys) {
        std::string publicHex = generatePublicKey(entry.second);
        if (publicHex.empty()) {
            std::cerr << "Failed to generate public key for key " << keyIndex << std::endl;
            continue;
        }
        oss << "256-bit ECC Public Key " << keyIndex << ":\n";
        oss << publicHex << "\n";
        if (keyIndex < static_cast<int>(keys.size()))
            oss << "----------------------------------------------------------------------------------------------\n";
        keyIndex++;
    }

    std::ostringstream outputFilename;
    outputFilename << folder << "/ECC_public_key_" << maxNumber << ".txt";
    std::ofstream outfile(outputFilename.str());
    if (!outfile) {
        std::cerr << "Failed to open output file " << outputFilename.str() << std::endl;
        return 1;
    }
    outfile << oss.str();
    outfile.close();

    std::cout << "Public key(s) generated and written to " << outputFilename.str() << std::endl;
    return 0;
}
