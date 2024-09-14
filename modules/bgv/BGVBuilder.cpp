// BGVBuilder.cpp
#include "BGVBuilder.h"

BGVBuilder::BGVBuilder(const seal::sec_level_type sec_level, const size_t poly_modulus_degree, const std::vector<int> bit_sizes, const bool use_ntt) {
    if (bit_sizes.size() == 0) {
        throw std::invalid_argument("bit_sizes vector is empty");
    }
    else {
        int total_bit_size = 0;
        int max_bit_size = seal::CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level);

        for (auto& bit_size : bit_sizes) {
            total_bit_size += bit_size;
        }

        if (total_bit_size > max_bit_size) {
            throw std::runtime_error("total_bit_size exceeds MaxBitCount for the given poly_modulus_degree and security level");
        }

        seal::EncryptionParameters context_param(seal::scheme_type::bgv);
        context_param.set_poly_modulus_degree(poly_modulus_degree);
        context_param.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, bit_sizes));
        context_param.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));

        use_ntt_ = use_ntt;
        context_ = std::make_unique<seal::SEALContext>(context_param, true, sec_level);
        key_generator_ = std::make_unique<seal::KeyGenerator>(*context_);
        secret_key_ = seal::SecretKey();
        public_key_ = seal::PublicKey();
        relin_keys_ = seal::RelinKeys();
        galois_keys_ = seal::GaloisKeys();
    }
}

BGVBuilder& BGVBuilder::create_secret_key() {
    secret_key_ = key_generator_->secret_key();
    return *this;
}

BGVBuilder& BGVBuilder::create_public_key() {
    key_generator_->create_public_key(public_key_);
    return *this;
}

BGVBuilder& BGVBuilder::create_relin_keys() {
    key_generator_->create_relin_keys(relin_keys_);
    return *this;
}

BGVBuilder& BGVBuilder::create_galois_keys(std::vector<int> steps) {
    key_generator_->create_galois_keys(steps, galois_keys_);
    return *this;
}

BGVSeal& BGVBuilder::build() {
    try {
        auto encoder = std::make_unique<seal::BatchEncoder>(*context_, use_ntt_);
        auto encryptor = std::make_unique<seal::Encryptor>(*context_, public_key_);
        auto decryptor = std::make_unique<seal::Decryptor>(*context_, secret_key_);
        auto evaluator = std::make_unique<seal::Evaluator>(*context_);

        return *(new BGVSeal(
            std::move(context_),
            std::move(encoder),
            std::move(encryptor),
            std::move(decryptor),
            std::move(evaluator),
            secret_key_,
            public_key_,
            relin_keys_,
            galois_keys_
        ));
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to build BGVSeal: " << e.what() << std::endl;
    }
}