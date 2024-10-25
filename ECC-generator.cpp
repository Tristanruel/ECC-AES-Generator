#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <bitset>
#include <filesystem>
#include <gmpxx.h>
#include <cstddef>
// #include <algorithm>
// g++ -static-libgcc -static-libstdc++ -o ECC-generator ECC-generator.cpp -lgmp

struct Point {
    mpz_t x;
    mpz_t y;
    bool infinity;

    Point() : infinity(true) {
        mpz_init(x);
        mpz_init(y);
    }

    Point(const mpz_t x_init, const mpz_t y_init) : infinity(false) {
        mpz_init_set(x, x_init);
        mpz_init_set(y, y_init);
    }

    Point(const Point &P) : infinity(P.infinity) {
        mpz_init_set(x, P.x);
        mpz_init_set(y, P.y);
    }

    Point& operator=(const Point &P) {
        if (this != &P) {
            mpz_set(x, P.x);
            mpz_set(y, P.y);
            infinity = P.infinity;
        }
        return *this;
    }

    ~Point() {
        mpz_clear(x);
        mpz_clear(y);
    }
};

void point_double(Point &R, const Point &P, const mpz_t p, const mpz_t a);
void point_add(Point &R, const Point &P, const Point &Q, const mpz_t p, const mpz_t a);
bool point_mul(Point &R, const mpz_t k, const Point &P, const mpz_t p, const mpz_t a);

void point_double(Point &R, const Point &P, const mpz_t p, const mpz_t a) {
    if (P.infinity) {
        R.infinity = true;
        return;
    }

    if (mpz_cmp_ui(P.y, 0) == 0) {
        R.infinity = true;
        return;
    }

    mpz_t lambda, temp1, temp2;
    mpz_inits(lambda, temp1, temp2, NULL);

    mpz_powm_ui(temp1, P.x, 2, p);
    mpz_mul_ui(temp1, temp1, 3);
    mpz_add(temp1, temp1, a);
    mpz_mod(temp1, temp1, p);

    mpz_mul_ui(temp2, P.y, 2);
    mpz_mod(temp2, temp2, p);

    if (mpz_invert(temp2, temp2, p) == 0) {
        R.infinity = true;
        mpz_clears(lambda, temp1, temp2, NULL);
        return;
    }
    mpz_mul(lambda, temp1, temp2);
    mpz_mod(lambda, lambda, p);

    mpz_powm_ui(R.x, lambda, 2, p);
    mpz_submul_ui(R.x, P.x, 2);
    mpz_mod(R.x, R.x, p);

    mpz_sub(R.y, P.x, R.x);
    mpz_mul(R.y, lambda, R.y);
    mpz_sub(R.y, R.y, P.y);
    mpz_mod(R.y, R.y, p);

    R.infinity = false;

    mpz_clears(lambda, temp1, temp2, NULL);
}

void point_add(Point &R, const Point &P, const Point &Q, const mpz_t p, const mpz_t a) {
    if (P.infinity) {
        R = Q;
        return;
    }
    if (Q.infinity) {
        R = P;
        return;
    }

    if (mpz_cmp(P.x, Q.x) == 0) {
        mpz_t temp1;
        mpz_init(temp1);
        mpz_neg(temp1, Q.y);
        mpz_mod(temp1, temp1, p);
        if (mpz_cmp(P.y, temp1) == 0) {
            R.infinity = true;
            mpz_clear(temp1);
            return;
        } else {
            point_double(R, P, p, a);
            mpz_clear(temp1);
            return;
        }
    }

    mpz_t lambda, temp;
    mpz_inits(lambda, temp, NULL);

    mpz_sub(temp, Q.x, P.x);
    mpz_mod(temp, temp, p);
    if (mpz_invert(temp, temp, p) == 0) {
        R.infinity = true;
        mpz_clears(lambda, temp, NULL);
        return;
    }

    mpz_sub(lambda, Q.y, P.y);
    mpz_mod(lambda, lambda, p);
    mpz_mul(lambda, lambda, temp);
    mpz_mod(lambda, lambda, p);

    mpz_powm_ui(R.x, lambda, 2, p);
    mpz_sub(R.x, R.x, P.x);
    mpz_sub(R.x, R.x, Q.x);
    mpz_mod(R.x, R.x, p);

    mpz_sub(R.y, P.x, R.x);
    mpz_mul(R.y, lambda, R.y);
    mpz_sub(R.y, R.y, P.y);
    mpz_mod(R.y, R.y, p);

    R.infinity = false;

    mpz_clears(lambda, temp, NULL);
}

bool point_mul(Point &R, const mpz_t k, const Point &P, const mpz_t p, const mpz_t a) {
    R.infinity = true;
    Point N(P);

    size_t nbits = mpz_sizeinbase(k, 2);

    for (ptrdiff_t i = nbits - 1; i >= 0; i--) {
        point_double(R, R, p, a);
        if (mpz_tstbit(k, i)) {
            point_add(R, R, N, p, a);
        }
    }

    return !R.infinity;
}

bool read_binary_code(const std::string &filename, mpz_t result) {
    std::ifstream infile(filename, std::ios::binary);
    if (!infile) {
        return false;
    }

    std::string binary_string;
    std::getline(infile, binary_string);
    infile.close();

    binary_string.erase(std::remove_if(binary_string.begin(), binary_string.end(), ::isspace), binary_string.end());

    for (char c : binary_string) {
        if (c != '0' && c != '1') {
            return false;
        }
    }

    mpz_set_str(result, binary_string.c_str(), 2);
    return true;
}

int main() {
    mpz_t p, a, b, Gx, Gy, n, h, n_minus_one;
    mpz_inits(p, a, b, Gx, Gy, n, h, n_minus_one, NULL);

    // (secp256r1)
    mpz_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    mpz_set_str(a, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    mpz_set_str(b, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    mpz_set_str(Gx, "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    mpz_set_str(Gy, "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CB8B7AEB8E8701D8DB4A4E6DCDD1571", 16);
    mpz_set_str(n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    mpz_set_ui(h, 1);

    mpz_sub_ui(n_minus_one, n, 1);

    std::string randomness_dir = "Randomness";
    std::vector<std::filesystem::path> randomness_files;

    for (const auto & entry : std::filesystem::directory_iterator(randomness_dir)) {
        if (entry.is_regular_file()) {
            randomness_files.push_back(entry.path());
        }
    }

    if (randomness_files.size() < 2) {
        std::cerr << "Not enough randomness files in 'Randomness' folder.\n";
        mpz_clears(p, a, b, Gx, Gy, n, h, n_minus_one, NULL);
        return 1;
    }

    std::sort(randomness_files.begin(), randomness_files.end());

    std::filesystem::path file1 = randomness_files[0];
    std::filesystem::path file2 = randomness_files[1];

    std::cout << "Using " << file1.filename().string() << " for ECC key 1\n";
    std::cout << "Using " << file2.filename().string() << " for ECC key 2\n";

    mpz_t d1, d2;
    mpz_inits(d1, d2, NULL);

    if (!read_binary_code(file1.string(), d1)) {
        std::cerr << "Failed to read binary code from " << file1.string() << "\n";
        mpz_clears(p, a, b, Gx, Gy, n, h, n_minus_one, d1, d2, NULL);
        return 1;
    }
    if (!read_binary_code(file2.string(), d2)) {
        std::cerr << "Failed to read binary code from " << file2.string() << "\n";
        mpz_clears(p, a, b, Gx, Gy, n, h, n_minus_one, d1, d2, NULL);
        return 1;
    }

    std::cout << "Deleting " << file1.filename().string() << "\n";
    std::filesystem::remove(file1);
    std::cout << "Deleting " << file2.filename().string() << "\n\n";
    std::filesystem::remove(file2);

    mpz_mod(d1, d1, n_minus_one);
    mpz_add_ui(d1, d1, 1);

    mpz_mod(d2, d2, n_minus_one);
    mpz_add_ui(d2, d2, 1);

    Point G(Gx, Gy);
    Point Q1, Q2;

    point_mul(Q1, d1, G, p, a);
    std::cout << "\033[32m" "ECC Key 1 successfully generated!\n" << "\033[0m";

    point_mul(Q2, d2, G, p, a);
    std::cout << "\033[32m" "ECC Key 2 successfully generated!\n" << "\033[0m";

    std::string ecc_keys_dir = "ECC Keys";
    std::filesystem::create_directories(ecc_keys_dir);

    int max_x = 0;
    for (const auto& entry : std::filesystem::directory_iterator(ecc_keys_dir)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().filename().string();
            std::string prefix = "ECC_key_pair_";
            std::string suffix = ".txt";
            if (filename.compare(0, prefix.size(), prefix) == 0 && filename.size() > prefix.size() + suffix.size()) {
                std::string x_str = filename.substr(prefix.size(), filename.size() - prefix.size() - suffix.size());
                try {
                    int x = std::stoi(x_str);
                    if (x > max_x) {
                        max_x = x;
                    }
                } catch (const std::invalid_argument& e) {
                    continue;
                }
            }
        }
    }

    int new_x = max_x + 1;
    std::string output_filename = ecc_keys_dir + "/ECC_key_pair_" + std::to_string(new_x) + ".txt";

    std::ofstream outfile(output_filename);
    if (!outfile) {
        std::cerr << "Failed to open output file: " << output_filename << "\n";
        mpz_clears(p, a, b, Gx, Gy, n, h, n_minus_one, d1, d2, NULL);
        return 1;
    }
    
    std::cout << "\033[32m" << output_filename << " successfully generated!\n\n" << "\033[0m";

    outfile << "256-bit ECC Key 1 (Private Key):\n";

    char *d1_str = mpz_get_str(NULL, 16, d1);
    outfile << d1_str << "\n";

    outfile << "----------------------------------------------------------------------------------------------\n";
    outfile << "256-bit ECC Key 2 (Private Key):\n";

    char *d2_str = mpz_get_str(NULL, 16, d2);
    outfile << d2_str << "\n";
    outfile.close();

    std::cout << "ECC Key 1 (Private Key): " << d1_str << "\n";
    std::cout << "ECC Key 2 (Private Key): " << d2_str << "\n";
/*
    if (!Q1.infinity) {
        char *Q1_x_str = mpz_get_str(NULL, 16, Q1.x);
        char *Q1_y_str = mpz_get_str(NULL, 16, Q1.y);
        std::cout << "ECC Key 1 (Public Key): (" << Q1_x_str << ", " << Q1_y_str << ")\n";
        free(Q1_x_str);
        free(Q1_y_str);
    } else {
        std::cout << "ECC Key 1 (Public Key): Point at Infinity\n";
    }

    if (!Q2.infinity) {
        char *Q2_x_str = mpz_get_str(NULL, 16, Q2.x);
        char *Q2_y_str = mpz_get_str(NULL, 16, Q2.y);
        std::cout << "ECC Key 2 (Public Key): (" << Q2_x_str << ", " << Q2_y_str << ")\n";
        free(Q2_x_str);
        free(Q2_y_str);
    } else {
        std::cout << "ECC Key 2 (Public Key): Point at Infinity\n";
    }
*/
    free(d1_str);
    free(d2_str);

    

    mpz_clears(p, a, b, Gx, Gy, n, h, n_minus_one, d1, d2, NULL);

    return 0;
}
