// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;


void create_pattern(vector<int64_t>& pattern, size_t& pattern_size) {
    pattern_size = 4;
    pattern.assign(pattern_size, 0);
    pattern[0] = 1;
    pattern[1] = -1;
    pattern[2] = -1;
    pattern[3] = 1;
}


void create_text(vector<int64_t>& text, size_t& text_size) {
    text_size = 8;
    text.assign(text_size, 0);
    text[text_size - 1] = 1;
    text[text_size - 2] = -1;
    text[text_size - 3] = -1;
    text[text_size - 4] = 1;
    text[text_size - 5] = 1;
    text[text_size - 6] = -1;
    text[text_size - 7] = -1;
    text[text_size - 8] = 1;
}


void create_magnification(mt19937 &random_generator, int64_t& magnification) {
    magnification = uniform_int_distribution<int>(1, 1000)(random_generator);
}


void create_noise(mt19937& random_generator, int64_t magnification, int64_t& noise) {
    noise = uniform_int_distribution<int>(0, magnification - 1)(random_generator);
}


void main()
{
    /*
    * Create bgv scheme
    */
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    BatchEncoder batch_encoder(context);
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

    size_t calc_size = pattern_size + text_size - 1;
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