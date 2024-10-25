#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <bitset>
#include <filesystem> 

using namespace std;
namespace fs = std::filesystem; 

vector<int> vonNeumannExtract(const vector<int>& input) {
    vector<int> output;
    for (size_t i = 0; i + 1 < input.size(); i += 2) {
        if (input[i] != input[i + 1]) {
            output.push_back(input[i]);
        }
    }
    return output;
}

int main() {
    ifstream file("Radiation Data/20241024_23_01_35.csv");
    string line;
    vector<int> all_bits;

    if (!file.is_open()) {
        cout << "Error opening file." << endl;
        return 1;
    }

    while (getline(file, line)) {
        size_t pos = 0;
        string token;
        while ((pos = line.find(',')) != string::npos) {
            token = line.substr(0, pos);
            int num = stoi(token);
            bitset<8> binary(num); 
            for (int i = 7; i >= 0; --i) {
                all_bits.push_back(binary[i]);
            }
            line.erase(0, pos + 1);
        }
        if (!line.empty()) {
            int num = stoi(line);
            bitset<8> binary(num);
            for (int i = 7; i >= 0; --i) {
                all_bits.push_back(binary[i]);
            }
        }
    }

    file.close();

    string directory_path = "Randomness";
    fs::create_directory(directory_path); 

    cout << "We have " << all_bits.size() << " bits of data" << endl;

    vector<int> unbiased_bits = vonNeumannExtract(all_bits);
    int num_keys = unbiased_bits.size() / 256;

    cout << "We can create " << num_keys << " 256-bit random key generation files" << endl;

    for (int i = 0; i < num_keys; ++i) {
        ofstream out(directory_path + "/Von_Neumann_randomness_" + to_string(i + 1) + ".txt");
        int start = i * 256;
        for (int j = start; j < start + 256; ++j) {
            out << unbiased_bits[j];
        }
        out.close();
        cout << "Lines " << start + 1 << "-" << start + 256 << " will be used for Von_Neumann_randomness_" << (i + 1) << ".txt" << endl;
    }

    cout << "Processing..." << endl;
    for (int i = 0; i < num_keys; ++i) {
        cout << "Von_Neumann_randomness_" << (i + 1) << ".txt" << endl;
    }

    return 0;
}
