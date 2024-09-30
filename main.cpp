// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "modules/bgv/BGVBuilder.h"
#include "modules/bgv/BGVSeal.h"
#include "modules/random/RandomGenerator.h"
#include "modules/algorithm/Huffman.h"
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <chrono>
#include <thread>

using namespace std;
using namespace seal;


string hashing_sha256(string data) {
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
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 4096, { 39, 30, 39 }, 40, false)
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
    //text = { 1, 1, -1, -1 };
    //pattern = { 1, 1 };
    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 8192, { 40, 30, 30, 40 }, 35, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    /*
    * Get plain modulus value
    */
    int64_t p = bgv_seal.plain_modulus_value();


    /*
    * Encrypt pattern (cipher)
    */
    Ciphertext pattern_encrypt = bgv_seal.encrypt(bgv_seal.encode(pattern));


    /*
    * Calculate
    */ 
    std::reverse(text.begin(), text.end());
    Plaintext text_plain = bgv_seal.encode(text);
 
    vector<int64_t> r = random_gen.get_integer_vector(1, p / 2, text.size());

    vector<string> hash;
    hash.reserve(text.size());
    for (auto& e : r) {
        hash.push_back(hashing_sha256(to_string(e)));
    }

    Ciphertext result_encrypt = bgv_seal.multiply(pattern_encrypt, text_plain);
    result_encrypt = bgv_seal.sub(result_encrypt, bgv_seal.encode(vector<int64_t>(text.size(), pattern.size())));
    result_encrypt = bgv_seal.add(result_encrypt, bgv_seal.encode(r));


    /*
    * Find pattern in text
    */
    vector<int64_t> pl;
    vector<int64_t> result = bgv_seal.decode(bgv_seal.decrypt(result_encrypt));

    for (int i = 0; i < text.size(); i++) {
        if (hashing_sha256(to_string(result[i])) == hash[i]) {
            pl.push_back((int64_t)text.size() - i - 1);
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


void pattern_matching_using_rotation( RandomGenerator& random_gen, vector<int64_t> text, vector<int64_t> pattern) {
    /*
    * Create rotation steps
    */
    vector<int> steps;
    for (int i = 1; i < pattern.size(); i <<= 1) {
        steps.push_back(i);
    }


    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 8192, { 40, 30, 30, 30, 40 }, 35, true)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .create_galois_keys(steps)
        .build();


    /*
    * Get plain modulus value
    */
    int64_t p = bgv_seal.plain_modulus_value();


    /*
    * Encrypt pattern (cipher)
    */
    vector<int64_t> pattern_repeat(text.size());

    for (int64_t i = 0, j = 0; i < pattern_repeat.size(); ++i, (++j) %= pattern.size()) {
        pattern_repeat[i] = pattern[j];
    }

    Ciphertext pattern_cipher = bgv_seal.encrypt(bgv_seal.encode(pattern_repeat));


    /*
    * Calculate
    */
    vector<Ciphertext> results;
    Plaintext text_plain = bgv_seal.encode(text);

    for (int r = 0; r < pattern.size(); r++, pattern_cipher = bgv_seal.rotate(pattern_cipher, 1)) {
        // Multiply encrypted pattern with plain text: enc([p1, p2, ..., pn]) * [t1, t2, ..., tn]
        Ciphertext result_cipher = bgv_seal.multiply(pattern_cipher, text_plain);

        // Compute the range sum for result. If the part matches, it will result in 'n'
        result_cipher = bgv_seal.range_sum(result_cipher, pattern.size());

        // Subtract pattern length: -[n, n, ..., n]
        result_cipher = bgv_seal.sub(result_cipher, bgv_seal.encode(vector<int64_t>(text.size(), pattern.size())));

        // Multiply by random data: *[r1, r2, ..., rn]
        result_cipher = bgv_seal.multiply(result_cipher, bgv_seal.encode(random_gen.get_integer_vector(1, p / 2, text.size())));
        results.push_back(result_cipher);
    }


    /*
    * Find pattern in text
    */
    vector<int64_t> pl;

    for (int r = 0; r < pattern.size(); r++) {
        Plaintext result_decrypted = bgv_seal.decrypt(results[r]);
        vector<int64_t> result_decoded = bgv_seal.decode(result_decrypted);
        //print_vector(result_decoded, text.size());

        for (int i = 0; i < (int)text.size() - r; i += pattern.size()) {
            if (i - r < 0) continue;
            if (result_decoded[i - r] == 0) {
                pl.push_back(i - r);
            }
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


void pattern_matching_using_rotation_2(RandomGenerator& random_gen, vector<int64_t> text, vector<int64_t> pattern) {
    //text = { 1, 1, -1, -1 };
    //pattern = { 1, 1 };
    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 8192, { 40, 30, 30, 40 }, 35, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    /*
    * Get plain modulus value
    */
    int64_t p = bgv_seal.plain_modulus_value();


    /*
    * Encrypt pattern (cipher)
    */
    vector<int64_t> pattern_repeat(text.size());

    for (int64_t i = 0, j = 0; i < pattern_repeat.size(); ++i, (++j) %= pattern.size()) {
        pattern_repeat[i] = pattern[j];
    }

    Ciphertext pattern_cipher = bgv_seal.encrypt(bgv_seal.encode(pattern_repeat));


    /*
    * Calculate
    */
    vector<Ciphertext> results;
    vector<vector<string>> hashes(pattern.size());
    vector<int64_t> text_rotate(text.size());
    vector<int64_t> g(pattern.size());
    vector<int64_t> r;

    for (int rot = 0; rot < pattern.size(); rot++) {
        for (int64_t i = 0, j = 0; i < text_rotate.size(); ++i, (++j) %= pattern.size()) {
            text_rotate[i] = text[(i + rot) % text.size()];
        }

        for (int64_t i = 0, involution = 1; i < g.size(); ++i, involution <<= 1) {
            g[i] = involution;
        }

        r = random_gen.get_integer_vector(1, p / 2, text.size());
        hashes[rot].reserve(text.size());
        for (auto& e : r) {
            hashes[rot].push_back(hashing_sha256(to_string(e)));
            //cout << '(' << e << ", " << hashing_sha256(to_string(e)) << ')' << ' ';
        }
        //cout << '\n';

        Plaintext text_plain = bgv_seal.encode(text_rotate);
        Plaintext g_plain = bgv_seal.encode(g);
        Plaintext r_plain = bgv_seal.encode(r);

        //print_vector(bgv_seal.decode(bgv_seal.decrypt(pattern_cipher)), text.size());
        //print_vector(bgv_seal.decode(text_plain), text.size());
        //print_vector(bgv_seal.decode(g_plain), text.size());
        //print_vector(bgv_seal.decode(r_plain), text.size());
        //print_vector(hashes[rot], text.size());

        // Subtract encrypted pattern with plain text: enc([p1, p2, ..., pn]) - [t1, t2, ..., tn]
        Ciphertext result_cipher = bgv_seal.sub(pattern_cipher, text_plain);
        //print_vector(bgv_seal.decode(bgv_seal.decrypt(result_cipher)), text.size());
    
        // Compute the range sum for result. If the part matches, it will result in '0'
        result_cipher = bgv_seal.multiply(result_cipher, g_plain);
        //print_vector(bgv_seal.decode(bgv_seal.decrypt(result_cipher)), text.size());

        // Add random value.
        result_cipher = bgv_seal.add(result_cipher, r_plain);
        //print_vector(bgv_seal.decode(bgv_seal.decrypt(result_cipher)), text.size());

        results.push_back(result_cipher);
        //cout << "===================\n";
    }


    /*
    * Find pattern in text
    */
    vector<int64_t> pl;

    for (int rot = 0; rot < pattern.size(); rot++) {
        vector<int64_t> result = bgv_seal.decode(bgv_seal.decrypt(results[rot]));
        //print_vector(result, text.size());

        for (int i = (int)pattern.size() - 1; i < (int)text.size() - rot; i += pattern.size()) {
            //cout << '(' << i << ", " << result[i] << ", " << hashing_sha256(to_string(result[i])) << ')' << ' ';
            if (hashing_sha256(to_string(result[i])) == hashes[rot][i]) {
                pl.push_back((int64_t)i - pattern.size() + 1 + rot);
            }
        }
        //cout << "===================\n";
    }

    if (pl.empty()) {
        cout << endl << "    [ empty ]" << endl << endl;
    }
    else {
        sort(pl.begin(), pl.end());
        print_vector(pl, pl.size());
    }
}


void pattern_matching_5(RandomGenerator& random_gen, vector<int64_t> text, vector<int64_t> pattern) {
    //text = { 0, 1, 2, 3, 4, 0, 1, 2, 3, 4,0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4 };
    //pattern = { 2, 3, 4 };

    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 8192, { 40, 30, 30, 40 }, 35, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    /*
    * Get plain modulus value
    */
    int64_t p = bgv_seal.plain_modulus_value();


    /*
    * Encrypt pattern (cipher)
    */
    vector<int64_t> pattern_repeat(text.size());

    for (int64_t i = 0, j = 0; i < pattern_repeat.size(); ++i, (++j) %= pattern.size()) {
        pattern_repeat[i] = pattern[j];
    }

    Ciphertext pattern_repeat_cipher = bgv_seal.encrypt(bgv_seal.encode(pattern_repeat));


    /*
    * Calculate
    */
    vector<Ciphertext> results_cipher;
    vector<int64_t> text_rotate(text.size());

    for (int rot = 0; rot < pattern.size(); rot++) {
        for (int64_t i = 0, j = 0; i < text_rotate.size(); ++i, (++j) %= pattern.size()) {
            text_rotate[i] = text[(i + rot) % text.size()];
        }

        Plaintext text_plain = bgv_seal.encode(text_rotate);
        Plaintext poly_plain = bgv_seal.encode(random_gen.get_integer_vector(-p / 2, p / 2, pattern.size()));

        // Subtract encrypted pattern with plain text: enc([p1, p2, ..., pn]) - [t1, t2, ..., tn]
        Ciphertext result_cipher = bgv_seal.sub(pattern_repeat_cipher, text_plain);

        // Compute the range sum for result. If the part matches, it will result in '0'
        result_cipher = bgv_seal.multiply(result_cipher, poly_plain);

        results_cipher.push_back(result_cipher);
    }


    /*
    * Find pattern in text
    */
    vector<int64_t> pattern_location;

    for (int rot = 0; rot < pattern.size(); rot++) {
        vector<int64_t> result = bgv_seal.decode(bgv_seal.decrypt(results_cipher[rot]));

        for (int i = (int)pattern.size() - 1; i < (int)text.size() - rot; i += pattern.size()) {
            if (result[i] == 0) {
                pattern_location.push_back((int64_t)i - pattern.size() + 1 + rot);
            }
        }
    }

    if (pattern_location.empty()) {
        cout << endl << "    [ empty ]" << endl << endl;
    }
    else {
        sort(pattern_location.begin(), pattern_location.end());
        print_vector(pattern_location, pattern_location.size());
    }
}

void pattern_matching_6(RandomGenerator& random_gen, vector<int64_t> text, vector<int64_t> pattern) {
    //text = { 0, 1, 2, 3, 4, 0, 1, 2, 3, 4};
    //pattern = { 2, 3, 4 };
    /*
    * Create bgv seal
    */
    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 8192, { 40, 30, 30, 40 }, 35, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    /*
    * Get plain modulus value
    */
    int64_t p = bgv_seal.plain_modulus_value();


    /*
    * Convert to binary data
    */
    Huffman huffman(text);
    auto [text_convert, text_data_loc] = huffman.encode(text);
    auto [pattern_convert, pattern_data_loc] = huffman.encode(pattern);

    cout << text.size() << '\n';
    cout << text_convert.size() << '\n';
    cout << pattern.size() << '\n';
    cout << pattern_convert.size() << '\n';

    //for (auto& e : text) cout << e << ' '; cout << '\n';
    //for (auto& e : text_data_loc) cout << e << ' '; cout << '\n';
   // for (auto& e : text_convert) cout << e << ' '; cout << '\n';
   // for (auto& e : pattern_convert) cout << e << ' '; cout << '\n';
   

    text = text_convert;
    pattern = pattern_convert;
    for (auto& e : text) if (!e) e = -1;
    for (auto& e : pattern) if (!e) e = -1;


    /*
    * Encrypt pattern (cipher)
    */
    Ciphertext pattern_encrypt = bgv_seal.encrypt(bgv_seal.encode(pattern));


    /*
    * Calculate
    */
    vector<int64_t> r = random_gen.get_integer_vector(-(p / 2), p / 2, text.size());

    std::reverse(text.begin(), text.end());
    Plaintext text_plain = bgv_seal.encode(text);

    vector<string> hash;
    hash.reserve(text.size());
    for (auto& e : r) {
        hash.push_back(hashing_sha256(to_string(e)));
    }

    Ciphertext result_encrypt = bgv_seal.multiply(pattern_encrypt, text_plain);
    result_encrypt = bgv_seal.sub(result_encrypt, bgv_seal.encode(vector<int64_t>(text.size(), (int64_t)pattern.size())));
    result_encrypt = bgv_seal.add(result_encrypt, bgv_seal.encode(r));


    /*
    * Find pattern in text
    */
    vector<int64_t> pattern_location;
    vector<int64_t> result = bgv_seal.decode(bgv_seal.decrypt(result_encrypt));

    for (int i = 0, j = (int64_t)text_data_loc.size() - 1; i < text.size(); i++) {
        if (hashing_sha256(to_string(result[i])) == hash[i]) {
            int loc = (int64_t)text.size() - i - 1;
            while (j >= 0 && text_data_loc[j] > loc) { j--; }
            if (text_data_loc[j] == loc) {
                pattern_location.push_back(j);
            }
        }
    }

    if (pattern_location.empty()) {
        cout << endl << "    [ empty ]" << endl << endl;
    }
    else {
        sort(pattern_location.begin(), pattern_location.end());
        print_vector(pattern_location, pattern_location.size());
    }
}


void testing_binary_pattern_matching(const int text_size = 4096, const int pattern_size = 10) {
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
    /*
    cout << "- pattern_matching_using_magnification" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_using_magnification(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;*/



    cout << "- pattern_matching_using_hashing" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_using_hashing(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;


    cout << "- pattern_matching_5" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_5(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;


    cout << "- pattern_matching_6" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_6(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;

    /*cout << "- pattern_matching_using_rotation" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_using_rotation(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;


    cout << "- pattern_matching_using_rotation_2" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_using_rotation_2(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;*/
}


void testing_pattern_matching(const int text_size = 4096, const int pattern_size = 10) {
    cout << endl << "------------------ <Testing pattern matching : text size(" << text_size << "), pattern size(" << pattern_size << ")> ------------------" << endl << endl;

    /*
    * Generate random data
    */
    RandomGenerator random_gen;
    vector<int64_t> text = random_gen.get_integer_vector(0, 4, text_size);
    vector<int64_t> pattern = random_gen.get_integer_vector(0, 4, pattern_size);

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
    cout << "- pattern_matching_5" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_5(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;


    cout << "- pattern_matching_6" << endl;
    start = chrono::high_resolution_clock::now();
    pattern_matching_6(random_gen, text, pattern);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;
}



void main()
{
  /*  BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 8192, {40, 30, 30, 40}, 35, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();

    int64_t temp = bgv_seal.plain_modulus_value() / 2 + 1;
    cout << temp << '\n';
    vector<int64_t> temps({ temp, temp, temp });
    Plaintext p = bgv_seal.encode(temps);
    Ciphertext e = bgv_seal.encrypt(p);

    print_vector(bgv_seal.decode(p), 5);
    print_vector(bgv_seal.decode(bgv_seal.decrypt(e)), 5);
    print_vector(bgv_seal.decode(bgv_seal.decrypt(bgv_seal.add(e, e))), 5);*/

    /*RandomGenerator random_gen;
    std::vector<int64_t> data = random_gen.get_integer_vector(0, 25, 20);
    std::cout << "Origin Data:" << std::endl;
    for (const auto& val : data) {
        std::cout << val << " ";
    }
    std::cout << std::endl;


    // 허프만 인코더 생성
    Huffman huffman(data);

    // 데이터 인코딩
    auto [encoded, location] = huffman.encode(data);
    std::cout << "Encoded Data (0과 1):" << std::endl;
    for (const auto& bit : encoded) {
        std::cout << bit;
    }
    std::cout << std::endl;

    std::cout << "Location Data:" << std::endl;
    for (const auto& loc : location) {
        std::cout << loc;
    }
    std::cout << std::endl;

    // 데이터 디코딩
    std::vector<int64_t> decoded = huffman.decode(encoded);
    std::cout << "Decoded Data:" << std::endl;
    for (const auto& val : decoded) {
        std::cout << val << " ";
    }
    std::cout << std::endl;*/

    for (auto& pattern_size : vector<int>{ 5, 10, 20, 30, 40, 50 }) {
        //testing_pattern_matching(3000, pattern_size);
    }

    for (auto& pattern_size : vector<int>{ 5, 10, 20, 30, 40, 50 }) {
        testing_binary_pattern_matching(4096, pattern_size);
    }

    /*    BGVSeal& bgv_seal = BGVBuilder(seal::sec_level_type::tc128, 8192, {40, 30, 30, 40}, 35, false)
            .create_secret_key()
            .create_public_key()
            .create_relin_keys()
            .build();


        vector<int64_t> v1 = { 0, 0, 0, -16, 32, 64 };
        vector<int64_t> v2 = { 0, 0, 0 };

        Ciphertext c1 = bgv_seal.encrypt(bgv_seal.encode(v1));
        Ciphertext c2 = bgv_seal.encrypt(bgv_seal.encode(v2));

        print_vector(bgv_seal.decode(bgv_seal.decrypt(bgv_seal.multiply(c1, c2))), 10);*/
}