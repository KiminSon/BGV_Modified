// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
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


void create_pattern(vector<int64_t>& pattern, size_t& pattern_size) {
    pattern_size = 8;
    pattern.assign(pattern_size, 0);
    pattern[0] = 1;
    pattern[1] = -1;
    pattern[2] = -1;
    pattern[3] = 1;
    pattern[4] = 1;
    pattern[5] = -1;
    pattern[6] = -1;
    pattern[7] = 1;
}


void create_text(vector<int64_t>& text, size_t& text_size) {
    text_size = 30;
    text.assign(text_size, 0);
    text[text_size - 1] = 1;
    text[text_size - 2] = 1;
    text[text_size - 3] = 1;
    text[text_size - 4] = -1;
    text[text_size - 5] = -1;
    text[text_size - 6] = 1;
    text[text_size - 7] = 1;
    text[text_size - 8] = -1;
    text[text_size - 9] = -1;
    text[text_size - 10] = 1;
    text[text_size - 11] = 1;
    text[text_size - 12] = 1;
    text[text_size - 13] = 1;
    text[text_size - 14] = 1;
    text[text_size - 15] = -1;
    text[text_size - 16] = -1;
    text[text_size - 17] = 1;
    text[text_size - 18] = 1;
    text[text_size - 19] = -1;
    text[text_size - 20] = -1;
    text[text_size - 21] = -1;
    text[text_size - 22] = 1;
    text[text_size - 23] = -1;
    text[text_size - 24] = -1;
    text[text_size - 25] = 1;
    text[text_size - 26] = 1;
    text[text_size - 27] = -1;
    text[text_size - 28] = -1;
    text[text_size - 29] = 1;
    text[text_size - 30] = -1;
}


void create_magnification(mt19937 &random_generator, int64_t& magnification) {
    magnification = uniform_int_distribution<int>(1, 1000)(random_generator);
}


void create_noise(mt19937& random_generator, int64_t magnification, int64_t& noise) {
    noise = uniform_int_distribution<int>(0, magnification - 1)(random_generator);
}


void create_adder(mt19937& random_generator, int64_t& adder) {
    adder = uniform_int_distribution<int>(1, 1000)(random_generator);
}


void test1() {
    /*
    * Create bgv scheme
    */
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    BatchEncoder batch_encoder(context, false);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);


    /*
    * Create random generator
    */
    mt19937 random_generator(static_cast<unsigned int>(std::time(nullptr)));


    /*
    * Create Magnification
    */
    int64_t magnification;
    create_magnification(random_generator, magnification);
    cout << "Random Magnification:" << endl;
    cout << endl << "    [ " << magnification << " ]" << endl << endl;


    /*
    * Create text (plain)
    */
    size_t text_size;
    vector<int64_t> text;
    create_text(text, text_size);

    cout << "Text:" << endl;
    print_vector(text, text_size);

    Plaintext text_plain;
    for (auto& t : text) { t *= magnification; }
    batch_encoder.encode(text, text_plain);


    /*
    * Create pattern (cipher)
    */
    size_t pattern_size;
    vector<int64_t> pattern;
    create_pattern(pattern, pattern_size);

    cout << "Pattern:" << endl;
    print_vector(pattern, pattern_size);

    Plaintext pattern_plain;
    batch_encoder.encode(pattern, pattern_plain);

    Ciphertext pattern_encrypted;
    encryptor.encrypt(pattern_plain, pattern_encrypted);


    /*
    * Create noise (plain)
    */
    size_t noises_size = pattern_size + text_size - 1;
    vector<int64_t> noises(noises_size, 0);
    for (auto& noise : noises) { create_noise(random_generator, magnification, noise); }

    cout << "Random Noises:" << endl;
    print_vector(noises, noises_size);

    Plaintext noises_plain;
    batch_encoder.encode(noises, noises_plain);


    /*
    * Calculate
    */
    Ciphertext calc_encrypted;
    evaluator.multiply_plain(pattern_encrypted, text_plain, calc_encrypted);
    evaluator.add_plain(calc_encrypted, noises_plain, calc_encrypted);

    Plaintext decrypted_result;
    decryptor.decrypt(calc_encrypted, decrypted_result);

    size_t calc_size = text_size;
    vector<int64_t> calc;
    batch_encoder.decode(decrypted_result, calc);
    calc.resize(calc_size);

    cout << "Enc(pattern) * (text * magnification) + noises:" << endl;
    print_vector(calc, calc_size);


    /*
    * Find pattern in text
    */
    vector<int64_t> pl;
    for (int i = 0; i < calc_size; i++) {
        if (calc[i] < (int64_t)pattern_size * magnification) continue;
        pl.push_back(i);
    }
    cout << "Find pattern in text:" << endl;
    print_vector(pl, pl.size());
}


void test2() {
    /*
    * Create bgv scheme
    */
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    BatchEncoder batch_encoder(context, false);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);


    /*
    * Create random generator
    */
    mt19937 random_generator(static_cast<unsigned int>(std::time(nullptr)));


    /*
    * Create Magnification
    */
    int64_t magnification;
    create_magnification(random_generator, magnification);
    cout << "Random Magnification:" << endl;
    cout << endl << "    [ " << magnification << " ]" << endl << endl;


    /*
    * Create text (plain)
    */
    size_t text_size;
    vector<int64_t> text;
    create_text(text, text_size);

    cout << "Text:" << endl;
    print_vector(text, text_size);

    Plaintext text_plain;
    for (auto& t : text) { t *= magnification; }
    batch_encoder.encode(text, text_plain);


    /*
    * Create pattern (cipher)
    */
    size_t pattern_size;
    vector<int64_t> pattern;
    create_pattern(pattern, pattern_size);

    cout << "Pattern:" << endl;
    print_vector(pattern, pattern_size);

    Plaintext pattern_plain;
    batch_encoder.encode(pattern, pattern_plain);

    Ciphertext pattern_encrypted;
    encryptor.encrypt(pattern_plain, pattern_encrypted);


    /*
    * Create reducer (plain)
    */
    size_t reducers_size = text_size;
    vector<int64_t> reducers(reducers_size, pattern_size * magnification);

    cout << "Reducer:" << endl;
    print_vector(reducers, reducers_size);

    Plaintext reducers_plain;
    batch_encoder.encode(reducers, reducers_plain);


    /*
    * Create adder (plain)
    */
    size_t adder_size = text_size;
    vector<int64_t> adders(adder_size);
    for (auto& adder : adders) { create_adder(random_generator, adder); }

    cout << "Adder:" << endl;
    print_vector(adders, adder_size);

    Plaintext adders_plain;
    batch_encoder.encode(adders, adders_plain);


    /*
    * Calculate
    */
    Ciphertext calc_encrypted;
    evaluator.multiply_plain(pattern_encrypted, text_plain, calc_encrypted);
    evaluator.sub_plain(calc_encrypted, reducers_plain, calc_encrypted);
    evaluator.add_plain(calc_encrypted, adders_plain, calc_encrypted);

    Plaintext decrypted_result;
    decryptor.decrypt(calc_encrypted, decrypted_result);

    size_t calc_size = text_size;
    vector<int64_t> calc;
    batch_encoder.decode(decrypted_result, calc);
    calc.resize(calc_size);

    cout << "Hash(Enc(pattern) * (text * magnification) - reducer + adder):" << endl;
    print_vector(calc, calc_size);


    /*
    * hashing
    */
    vector<string> ph;
    for (auto& e : calc) {
        string s = to_string(e);
        ph.push_back(hashing_sha256(s));
    }
    cout << "Hashing:" << endl;
    print_vector(ph, ph.size());

    /*
    * Find pattern in text
    */
    vector<int64_t> pl;
    for (int i = 0; i < ph.size(); i++) {
        string s = to_string(adders_plain[i]);
        if (ph[i] != hashing_sha256(s)) continue;
        pl.push_back(i);
    }
    cout << "Find pattern in text:" << endl;
    print_vector(pl, pl.size());
}


void test3() {
    /*
    * Create bgv scheme
    */
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    BatchEncoder batch_encoder(context, true);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    GaloisKeys galois_keys;
    vector<int> steps = { -1 };
    keygen.create_galois_keys(steps, galois_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);


    /*
    * Create text (cipher)
    */
    size_t text_size;
    vector<int64_t> text;
    create_text(text, text_size);

    cout << "Text:" << endl;
    print_vector(text, text_size);

    Plaintext text_plain;
    batch_encoder.encode(text, text_plain);

    Ciphertext text_encrypted;
    encryptor.encrypt(text_plain, text_encrypted);


    /*
    * Create pattern (cipher)
    */
    size_t pattern_size;
    vector<int64_t> temp, pattern;
    create_pattern(temp, pattern_size);

    for (int i = 0; i < text_size/ pattern_size; i++) {
        pattern.insert(pattern.end(), temp.begin(), temp.end());
    }

    cout << "Pattern:" << endl;
    print_vector(pattern, text_size);

    Plaintext pattern_plain;
    batch_encoder.encode(pattern, pattern_plain);

    Ciphertext pattern_encrypted;
    encryptor.encrypt(pattern_plain, pattern_encrypted);


    /*
    * Calculate & Find pattern in text
    */
    vector<int64_t> pl;

    for (int i = 0; i < pattern_size; i++) {
        Ciphertext calc_encrypted;
        evaluator.multiply(pattern_encrypted, text_encrypted, calc_encrypted);
        evaluator.rotate_rows_inplace(pattern_encrypted, -1, galois_keys);

        Plaintext decrypted_result;
        decryptor.decrypt(calc_encrypted, decrypted_result);

        size_t calc_size = text_size;
        vector<int64_t> calc;
        batch_encoder.decode(decrypted_result, calc);
        calc.resize(calc_size);

        cout << "Rotate" << i << "(Enc(pattern)) - Enc(text):" << endl;
        print_vector(calc, calc_size);

        for (int i = 0, cnt = 0, sum = 0; i < calc_size; i++) {
            if (calc[i] == 0) continue;
            sum += calc[i];

            if (++cnt == pattern_size) {
                if (sum == pattern_size) {
                    pl.push_back(i);
                }
                sum = cnt = 0;
            }
        }
    }
   
    cout << "Find pattern in text:" << endl;
    sort(pl.begin(), pl.end());
    print_vector(pl, pl.size());
}


void main()
{
    auto start = chrono::high_resolution_clock::now();
    test1();
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> elapsed = end - start;
    cout << "Execution time: " << elapsed.count() << " ms" << endl;

    start = chrono::high_resolution_clock::now();
    test2();
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "Execution time: " << elapsed.count() << " ms" << endl;

    start = chrono::high_resolution_clock::now();
    test3();
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "Execution time: " << elapsed.count() << " ms" << endl;
}