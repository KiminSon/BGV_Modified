// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void main()
{
    print_example_banner("Example: BGV Basics");

    /*
    Note that scheme_type is now "bgv".
    */
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    We can certainly use BFVDefault coeff_modulus. In later parts of this example,
    we will demonstrate how to choose coeff_modulus that is more useful in BGV.
    */
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);

    /*
    Print the parameters that we have chosen.
    */
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    Batching and slot operations are the same in BFV and BGV.
    */
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    Here we create the following p:
    */
    vector<int64_t> p(slot_count, 0);
    p[0] = 1;
    p[1] = -1;
    p[2] = -1;
    p[3] = 1;

    cout << "Pattern vector:" << endl;
    print_vector(p, 10);
    Plaintext p_plain;
    batch_encoder.encode(p, p_plain);

    /*
    Here we create the following t:
    */
    vector<int64_t> t(slot_count, 1);
    t[slot_count - 1] = 1;
    t[slot_count - 2] = -1;
    t[slot_count - 3] = -1;
    t[slot_count - 4] = 1;
    t[slot_count - 5] = 1;
    t[slot_count - 6] = -1;
    t[slot_count - 7] = -1;
    t[slot_count - 8] = 1;

    cout << "Text vector:" << endl;
    print_vector(t, 10);
    Plaintext t_plain;
    batch_encoder.encode(t, t_plain);

    /*
    Next we encrypt the encoded p_plain.
    */
    Ciphertext p_encrypted;
    encryptor.encrypt(p_plain, p_encrypted);


    /*
    Now we multiply p and t
    */
    Ciphertext r_encrypted;
    evaluator.multiply_plain(p_encrypted, t_plain, r_encrypted);


    /*
    Next we decrypt the r_cipher.
    */
    Plaintext decrypted_result;
    decryptor.decrypt(r_encrypted, decrypted_result);
    vector<int64_t> r;
    batch_encoder.decode(decrypted_result, r);
    cout << "Decrypt result:" << endl;
    print_vector(r, 10);
}