#include <gmpxx.h>
#include <gmp.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <random>
#include <chrono>

struct RSAKeys {
    mpz_class e;
    mpz_class d;
    mpz_class n;
};

mpz_class generate_prime(int bits = 4096, int certainty = 25) {
    std::cout << "Generating a " << bits << "-bit prime number..." << std::endl;
    gmp_randclass rand_gen(gmp_randinit_default);
    
    std::random_device rd;
    unsigned long seed = rd();
    rand_gen.seed(seed);

    mpz_class prime;
    while (true) {
        prime = rand_gen.get_z_bits(bits);
        prime |= 1;
        mpz_setbit(prime.get_mpz_t(), bits - 1);
        if (mpz_probab_prime_p(prime.get_mpz_t(), certainty)) {
            std::cout << "Prime number generated." << std::endl;
            break;
        }
    }
    return prime;
}

bool mod_inverse(mpz_class& result, const mpz_class& a, const mpz_class& m) {
    return mpz_invert(result.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) != 0;
}

RSAKeys generate_keys(int bits = 4096) {
    std::cout << "Generating RSA keys with random primes..." << std::endl;

    mpz_class p = generate_prime(bits);
    mpz_class q;
    do {
        q = generate_prime(bits);
    } while (p == q);

    mpz_class n = p * q;
    mpz_class phi = (p - 1) * (q - 1);

    mpz_class e = 65537;
    mpz_class d;

    if (!mod_inverse(d, e, phi)) {
        throw std::runtime_error("Failed to compute modular inverse.");
    }

    RSAKeys keys{e, d, n};

    mpz_class check = (keys.e * keys.d) % phi;
    if (check != 1) {
        throw std::runtime_error("Invalid key generation: e * d mod phi != 1");
    } else {
        std::cout << "Verification passed: e * d mod phi = 1" << std::endl;
    }

    std::cout << "RSA keys generated successfully with random primes." << std::endl;
    std::cout << "Prime p: " << p.get_str() << std::endl;
    std::cout << "Prime q: " << q.get_str() << std::endl;
    std::cout << "Modulus n: " << n.get_str() << std::endl;
    std::cout << "Euler's Totient phi: " << phi.get_str() << std::endl;
    std::cout << "Public exponent e: " << e.get_str() << std::endl;
    std::cout << "Private exponent d: " << d.get_str() << std::endl;

    return keys;
}

mpz_class string_to_mpz(const std::string& message) {
    mpz_class m = 0;
    for (unsigned char c : message) {
        m <<= 8;
        m += c;
    }
    return m;
}

std::string mpz_to_string(const mpz_class& m) {
    std::string message;
    mpz_class temp = m;
    while (temp > 0) {
        mpz_class byte = temp & 0xFF;
        char c = static_cast<char>(byte.get_ui());
        message = c + message;
        temp >>= 8; 
    }
    return message;
}

mpz_class encrypt(const std::string& message, const RSAKeys& pub_key) {
    std::cout << "Encrypting the message..." << std::endl;
    mpz_class m = string_to_mpz(message);
    std::cout << "Message as integer (m): " << m.get_str() << std::endl;
    if (m >= pub_key.n) {
        throw std::runtime_error("Message is too long for the current key size.");
    }
    mpz_class c;
    mpz_powm(c.get_mpz_t(), m.get_mpz_t(), pub_key.e.get_mpz_t(), pub_key.n.get_mpz_t());
    std::cout << "Message encrypted successfully." << std::endl;
    return c;
}

std::string decrypt(const mpz_class& cipher, const RSAKeys& priv_key) {
    std::cout << "Decrypting the cipher..." << std::endl;
    mpz_class m;
    mpz_powm(m.get_mpz_t(), cipher.get_mpz_t(), priv_key.d.get_mpz_t(), priv_key.n.get_mpz_t());
    std::cout << "Decrypted integer (m): " << m.get_str() << std::endl;

    std::string message = mpz_to_string(m);
    if (message.empty()) {
        return "Decryption failed";
    }
    std::cout << "Cipher decrypted successfully." << std::endl;
    return message;
}

int main() {
    try {
        std::cout << "Starting RSA Program with Random Keys..." << std::endl;
        RSAKeys keys = generate_keys(4096);

        // Test 1: Single Character
        std::string message1 = "A";
        std::cout << "\nTest 1 - Single Character:" << std::endl;
        std::cout << "Original: " << message1 << std::endl;
        mpz_class cipher1 = encrypt(message1, keys);
        std::cout << "Encrypted Cipher: " << cipher1.get_str() << std::endl;
        std::string decrypted_message1 = decrypt(cipher1, keys);
        std::cout << "Decrypted: " << decrypted_message1 << std::endl;

        mpz_class m1 = string_to_mpz(message1);
        mpz_class m_decrypted1 = string_to_mpz(decrypted_message1);
        if (m1 == m_decrypted1) {
            std::cout << "Success: Decrypted message matches the original." << std::endl;
        } else {
            std::cout << "Error: Decrypted message does not match the original." << std::endl;
        }

        // Test 2: Multiple Characters
        std::string message2 = "Hello";
        std::cout << "\nTest 2 - Multiple Characters:" << std::endl;
        std::cout << "Original: " << message2 << std::endl;
        mpz_class cipher2 = encrypt(message2, keys);
        std::cout << "Encrypted Cipher: " << cipher2.get_str() << std::endl;
        std::string decrypted_message2 = decrypt(cipher2, keys);
        std::cout << "Decrypted: " << decrypted_message2 << std::endl;

        mpz_class m2 = string_to_mpz(message2);
        mpz_class m_decrypted2 = string_to_mpz(decrypted_message2);
        if (m2 == m_decrypted2) {
            std::cout << "Success: Decrypted message matches the original." << std::endl;
        } else {
            std::cout << "Error: Decrypted message does not match the original." << std::endl;
        }

        // Test 3: Longer Message
        std::string message3 = "This is a message that is being encoded";
        std::cout << "\nTest 3 - Longer Message:" << std::endl;
        std::cout << "Original: " << message3 << std::endl;
        mpz_class cipher3 = encrypt(message3, keys);
        std::cout << "Encrypted Cipher: " << cipher3.get_str() << std::endl;
        std::string decrypted_message3 = decrypt(cipher3, keys);
        std::cout << "Decrypted: " << decrypted_message3 << std::endl;

        mpz_class m3 = string_to_mpz(message3);
        mpz_class m_decrypted3 = string_to_mpz(decrypted_message3);
        if (m3 == m_decrypted3) {
            std::cout << "Success: Decrypted message matches the original." << std::endl;
        } else {
            std::cout << "Error: Decrypted message does not match the original." << std::endl;
        }

        std::cout << "\nMeasuring decryption time for Test 3 over 1 iteration..." << std::endl;
        auto start_time = std::chrono::high_resolution_clock::now();
        std::string decrypted_message_time = decrypt(cipher3, keys);
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end_time - start_time;
        std::cout << "Decryption time: " << elapsed.count() << " seconds" << std::endl;

        std::cout << "\nRSA Program Completed Successfully." << std::endl;

    } catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown Exception Occurred." << std::endl;
        return 1;
    }

    return 0;
}
