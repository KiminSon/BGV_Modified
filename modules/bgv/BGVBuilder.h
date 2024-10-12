// BGVBuilder.h
#pragma once

#include "seal/seal.h"
#include "BGVSeal.h"
#include <vector>
#include <memory>

class BGVBuilder {
public:
    BGVBuilder(
        const seal::sec_level_type sec_level,
        const size_t poly_modulus_degree,
        const std::vector<int> coeff_bit_sizes,
        const int plain_bit_size,
        const bool use_ntt
    );

    BGVBuilder& create_secret_key();

    BGVBuilder& create_public_key();

    BGVBuilder& create_relin_keys();

    BGVBuilder& create_galois_keys(std::vector<int> steps = {});

    BGVSeal& build();

private:
    bool use_ntt_;

    std::unique_ptr<seal::SEALContext> context_;

    std::unique_ptr<seal::KeyGenerator> key_generator_;

    seal::SecretKey secret_key_;

    seal::PublicKey public_key_;

    seal::RelinKeys relin_keys_;

    seal::GaloisKeys galois_keys_;
};