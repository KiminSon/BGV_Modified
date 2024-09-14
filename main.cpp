// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "modules/bgv/BGVBuilder.h"
#include "modules/bgv/BGVSeal.h"
#include "modules/random/RandomGenerator.h"
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <chrono>
#include <thread>

using namespace std;
using namespace seal;


string hashing_sha256(string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}


void pattern_matching_using_magnification(RandomGenerator& random_gen, vector<int64_t> text, vector<int64_t> pattern) {
    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 4096, { 39, 30, 39 }, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    /*
    * Create Magnification
    */
    int64_t magnification = random_gen.get_integer(std::pow<int64_t, int64_t>(2, 4), std::pow<int64_t, int64_t>(2, 5));


    /*
    * Encode text (plain)
    */
    std::reverse(text.begin(), text.end());
    for (auto& e : text) { e *= magnification; }
    Plaintext text_plain = bgv_seal.encode(text);


    /*
    * Encrypt pattern (cipher)
    */

    Plaintext pattern_plain = bgv_seal.encode(pattern);
    Ciphertext pattern_encrypted = bgv_seal.encrypt(pattern_plain);


    /*
    * Create noise (plain)
    */
    vector<int64_t> noises = random_gen.get_integer_vector(0, magnification - 1, text.size());
    Plaintext noises_plain = bgv_seal.encode(noises);


    /*
    * Calculate
    */
    Ciphertext calc = bgv_seal.multiply(pattern_encrypted, text_plain);
    bgv_seal.add(calc, noises_plain);

    Plaintext calc_decrypted = bgv_seal.decrypt(calc);
    vector<int64_t> calc_decoded = bgv_seal.decode(calc_decrypted);
    calc_decoded.resize(text.size());


    /*
    * Find pattern in text
    */
    vector<int64_t> pl;
    for (int i = 0; i < calc_decoded.size(); i++) {
        if (calc_decoded[i] < (int64_t)pattern.size() * magnification) continue;
        pl.push_back((int64_t)text.size() - i - 1);
    }

    if (pl.empty()) {
        cout << endl << "    [ empty ]" << endl << endl;
    }
    else {
        sort(pl.begin(), pl.end());
        print_vector(pl, pl.size());
    }
}


void pattern_matching_using_hashing(RandomGenerator& random_gen, vector<int64_t> text, vector<int64_t> pattern) {
    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 4096, { 39, 30, 39 }, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    /*
    * Create Magnification
    */
    int64_t magnification = random_gen.get_integer(std::pow<int64_t, int64_t>(2, 4), std::pow<int64_t, int64_t>(2, 5));


    /*
    * Encode text (plain)
    */
    std::reverse(text.begin(), text.end());
    for (auto& e : text) { e *= magnification; }
    Plaintext text_plain = bgv_seal.encode(text);


    /*
    * Encrypt pattern (cipher)
    */
    Plaintext pattern_plain = bgv_seal.encode(pattern);
    Ciphertext pattern_encrypted = bgv_seal.encrypt(pattern_plain);


    /*
    * Create reducer (plain)
    */
    vector<int64_t> reducers(text.size(), pattern.size() * magnification);
    Plaintext reducers_plain = bgv_seal.encode(reducers);


    /*
    * Create adder (plain)
    */
    vector<int64_t> adders = random_gen.get_integer_vector(std::pow<int64_t, int64_t>(2, 4), std::pow<int64_t, int64_t>(2, 5), text.size());
    Plaintext adders_plain = bgv_seal.encode(adders);


    /*
    * Calculate
    */
    Ciphertext calc = bgv_seal.multiply(pattern_encrypted, text_plain);
    calc = bgv_seal.sub(calc, reducers_plain);
    calc = bgv_seal.add(calc, adders_plain);

    Plaintext decrypted_calc = bgv_seal.decrypt(calc);
    vector<int64_t> calc_decoded = bgv_seal.decode(decrypted_calc);
    calc_decoded.resize(text.size());


    /*
    * hashing
    */
    vector<string> ph;
    for (auto& e : calc_decoded) {
        string s = to_string(e);
        ph.push_back(hashing_sha256(s));
    }


    /*
    * Find pattern in text
    */
    vector<int64_t> pl;
    for (int i = 0; i < ph.size(); i++) {
        string s = to_string(adders_plain[i]);
        if (ph[i] != hashing_sha256(s)) continue;
        pl.push_back((int64_t)text.size() - i - 1);
    }

    if (pl.empty()) {
        cout << endl << "    [ empty ]" << endl << endl;
    }
    else {
        sort(pl.begin(), pl.end());
        print_vector(pl, pl.size());
    }
}


void pattern_matching_using_rotation( RandomGenerator& random_gen, vector<int64_t> text, vector<int64_t> pattern) {
    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 4096, { 39, 30, 39 }, true)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .create_galois_keys({ -1 })
        .build();


    /*
    * Encrypt text (cipher)
    */
    Plaintext text_plain = bgv_seal.encode(text);
    Ciphertext text_encrypted = bgv_seal.encrypt(text_plain);


    /*
    * Encrypt pattern (cipher)
    */
    vector<int64_t> repeated_pattern;
    for (int i = 0; i < text.size() / pattern.size(); i++) {
        repeated_pattern.insert(repeated_pattern.end(), pattern.begin(), pattern.end());
    }
    Plaintext repeated_pattern_plain = bgv_seal.encode(repeated_pattern);
    Ciphertext repeated_pattern_encrypted = bgv_seal.encrypt(repeated_pattern_plain);


    /*
    * Calculate & Find pattern in text
    */
    vector<int64_t> pl;

    for (int r = 0; r < pattern.size(); r++) {
        Ciphertext calc = bgv_seal.multiply(repeated_pattern_encrypted, text_encrypted);
        Plaintext calc_decrypted = bgv_seal.decrypt(calc);
        vector<int64_t> calc_decoded = bgv_seal.decode(calc_decrypted);
        calc_decoded.resize(text.size());

        for (int i = r, sum = 0; i < calc_decoded.size(); i += pattern.size(), sum = 0) {
            for (int j = 0; j < pattern.size(); j++) {
                if (i + j < calc_decoded.size()) {
                    sum += calc_decoded[i + j];
                }
            }

            if (sum == pattern.size()) {
                pl.push_back(i);
            }
        }

        if (r < (int)pattern.size() - 1) {
            repeated_pattern_encrypted = bgv_seal.rotate(repeated_pattern_encrypted, -1);
        }
    }

    if (pl.empty()) {
        cout << endl << "    [ empty ]" << endl << endl;
    }
    else {
        sort(pl.begin(), pl.end());
        print_vector(pl, pl.size());
    }
}


void testing_pattern_matching(const int text_size = 4096, const int pattern_size = 10) {
    cout << endl << "------------------ <Testing pattern matching : text size(" << text_size << "), pattern size(" << pattern_size << ")> ------------------" << endl << endl;

    /*
    * Generate random data
    */
    RandomGenerator random_gen;
    vector<int64_t> text = random_gen.get_integer_vector({ -1, 1 }, text_size);
    vector<int64_t> pattern = random_gen.get_integer_vector({ -1, 1 }, pattern_size);

    cout << "Text:";
    print_vector(text, std::min(10, (int)text.size()));
    cout << "Pattern:";
    print_vector(pattern, std::min(10, (int)pattern.size()));


    /*
    * Create timer var
    */
    chrono::steady_clock::time_point start, end;
    chrono::duration<double, milli> elapsed;

    /*
    * Testing
    */
    cout << "- pattern_matching_using_magnification" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_using_magnification(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;

    
    cout << "- pattern_matching_using_hashing" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_using_hashing(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;


    cout << "- pattern_matching_using_rotation" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_using_rotation(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;
}


void main()
{
    for (auto& pattern_size : vector<int>{ 5, 10, 20, 30, 40, 50 }) {
        testing_pattern_matching(4096, pattern_size);
    }
}