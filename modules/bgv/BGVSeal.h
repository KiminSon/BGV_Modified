// BGVSeal.h
#pragma once

#include "seal/seal.h"
#include <vector>
#include <memory>

class BGVSeal
{
public:
    BGVSeal(
        std::unique_ptr<seal::SEALContext> context,
        std::unique_ptr<seal::BatchEncoder> encoder,
        std::unique_ptr<seal::Encryptor> encryptor,
        std::unique_ptr<seal::Decryptor> decryptor,
        std::unique_ptr<seal::Evaluator> evaluator,
        const seal::SecretKey& secret_key,
        const seal::PublicKey& public_key,
        const seal::RelinKeys& relin_keys,
        const seal::GaloisKeys& galois_keys
    );

    seal::Plaintext encode(const std::vector<int64_t>& vector);

    std::vector<int64_t> decode(const seal::Plaintext& plain);

    seal::Ciphertext encrypt(const seal::Plaintext& plain);

    seal::Plaintext decrypt(const seal::Ciphertext& cipher);

    void params_matching(seal::Ciphertext& ciphertext1, seal::Ciphertext& ciphertext2);

    void params_matching(seal::Ciphertext& ciphertext, seal::Plaintext& plaintext);
    
    uint64_t plain_modulus_prime();

    std::vector<uint64_t> plain_modulus_roots(int n, int k);

    seal::Ciphertext add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2);

    seal::Ciphertext add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext);

    seal::Ciphertext sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2);

    seal::Ciphertext sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext);

    seal::Ciphertext multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2);

    seal::Ciphertext multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext);

    seal::Ciphertext negate(const seal::Ciphertext& ciphertext);

    seal::Ciphertext rotate(const seal::Ciphertext& ciphertext, const int step);

    seal::Ciphertext range_sum(const seal::Ciphertext& ciphertext, const int range_size);

private:
    std::unique_ptr<seal::SEALContext> context_;

    std::unique_ptr<seal::BatchEncoder> encoder_;

    std::unique_ptr<seal::Encryptor> encryptor_;

    std::unique_ptr<seal::Decryptor> decryptor_;

    std::unique_ptr<seal::Evaluator> evaluator_;

    seal::SecretKey secret_key_;

    seal::PublicKey public_key_;

    seal::RelinKeys relin_keys_;

    seal::GaloisKeys galois_keys_;
};