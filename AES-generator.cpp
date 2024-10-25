#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <gmpxx.h>
#include <algorithm>
#include <cstdio>

namespace fs = std::filesystem;

int main() {
    try {
        std::vector<std::pair<int, std::string>> randomness_files;

        for (const auto& entry : fs::directory_iterator("Randomness")) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::string prefix = "Von_Neumann_randomness_";
                std::string suffix = ".txt";
                if (filename.find(prefix) == 0 && filename.substr(filename.length() - suffix.length()) == suffix) {
                    std::string x_str = filename.substr(
                        prefix.length(),
                        filename.length() - prefix.length() - suffix.length()
                    );
                    if (x_str.empty()) {
                        continue;
                    }
                    int x = std::stoi(x_str);
                    randomness_files.emplace_back(x, filename);
                }
            }
        }

        if (randomness_files.size() < 2) {
            return 1;
        }

        std::sort(randomness_files.begin(), randomness_files.end());

        auto selected_file1 = randomness_files[0];
        auto selected_file2 = randomness_files[1];

        std::string randomness_file_path1 = "Randomness/" + selected_file1.second;
        std::ifstream infile1(randomness_file_path1);
        if (!infile1) {
            return 1;
        }
        std::string binary_code1;
        infile1 >> binary_code1;
        infile1.close();

        if (binary_code1.length() != 256) {
            return 1;
        }

        std::string randomness_file_path2 = "Randomness/" + selected_file2.second;
        std::ifstream infile2(randomness_file_path2);
        if (!infile2) {
            return 1;
        }
        std::string binary_code2;
        infile2 >> binary_code2;
        infile2.close();

        if (binary_code2.length() != 256) {
            return 1;
        }

        mpz_class num1(binary_code1.c_str(), 2);
        mpz_class num2(binary_code2.c_str(), 2);

        mpz_class key = num1 ^ num2;

        std::string key_hex = key.get_str(16);

        if (key_hex.length() < 64) {
            key_hex = std::string(64 - key_hex.length(), '0') + key_hex;
        }

        std::cout << "Using " << selected_file1.second << " and " << selected_file2.second << " for AES Key generation" << std::endl;

        std::remove(randomness_file_path1.c_str());
        std::remove(randomness_file_path2.c_str());

        std::cout << "Deleting " << selected_file1.second << " " << std::endl;
        std::cout << "Deleting " << selected_file2.second << " " << std::endl;

        if (!fs::exists("AES Keys")) {
            fs::create_directory("AES Keys");
        }

        std::vector<int> aes_keys;
        for (const auto& entry : fs::directory_iterator("AES Keys")) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::string prefix = "AES_key_";
                std::string suffix = ".txt";
                if (filename.find(prefix) == 0 && filename.substr(filename.length() - suffix.length()) == suffix) {
                    std::string x_str = filename.substr(
                        prefix.length(),
                        filename.length() - prefix.length() - suffix.length()
                    );
                    if (x_str.empty()) {
                        continue;
                    }
                    int x_key = std::stoi(x_str);
                    aes_keys.push_back(x_key);
                }
            }
        }

        int max_x = 0;
        for (int x_key : aes_keys) {
            if (x_key > max_x) {
                max_x = x_key;
            }
        }
        int new_x = max_x + 1;

        std::string output_filename = "AES Keys/AES_key_" + std::to_string(new_x) + ".txt";
        std::ofstream outfile(output_filename);
        if (!outfile) {
            return 1;
        }
        outfile << "256-bit AES Key:\n" << key_hex << "\n";
        outfile << "----------------------------------------------------------------------------------------------\n";
        outfile.close();

        std::cout << "\033[32m" "\nAES Key successfully generated!\n" << "\033[0m";
        std::cout << "\033[32m" << output_filename << " successfully generated!\n\n" << "\033[0m";
        std::cout << "AES Key: " << key_hex << std::endl;

        return 0;
    }
    catch (...) {
        return 1;
    }
}
