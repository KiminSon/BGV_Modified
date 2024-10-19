// BGVSeal.cpp
#include "BGVSeal.h"

BGVSeal::BGVSeal(
    std::unique_ptr<seal::SEALContext> context,
    std::unique_ptr<seal::BatchEncoder> encoder,
    std::unique_ptr<seal::Encryptor> encryptor,
    std::unique_ptr<seal::Decryptor> decryptor,
    std::unique_ptr<seal::Evaluator> evaluator,
    const seal::SecretKey& secret_key,
    const seal::PublicKey& public_key,
    const seal::RelinKeys& relin_keys,
    const seal::GaloisKeys& galois_keys
)
    : context_(std::move(context)),
    encoder_(std::move(encoder)),
    encryptor_(std::move(encryptor)),
    decryptor_(std::move(decryptor)),
    evaluator_(std::move(evaluator)),
    secret_key_(secret_key),
    public_key_(public_key),
    relin_keys_(relin_keys),
    galois_keys_(galois_keys) {

}

uint64_t BGVSeal::plain_modulus_prime() {
    return context_->key_context_data()->parms().plain_modulus().value();
}

std::vector<uint64_t> BGVSeal::plain_modulus_roots(int n, int k) {
    std::vector<uint64_t> roots;

    if (n < 1 || (n & (n - 1)) != 0) {
        return roots;
    }

    seal::Modulus modulus = context_->key_context_data()->parms().plain_modulus();
    seal::util::try_primitive_roots(n, modulus, k, roots);

    return roots;
}

seal::Plaintext BGVSeal::encode(const std::vector<int64_t>& vector) {
    seal::Plaintext plain;
    encoder_->encode(vector, plain);
    return plain;
}

std::vector<int64_t> BGVSeal::decode(const seal::Plaintext& plaintext) {
    std::vector<int64_t> vector;
    encoder_->decode(plaintext, vector);
    return vector;
}

seal::Ciphertext BGVSeal::encrypt(const seal::Plaintext& plain) {
    seal::Ciphertext cipher;
    encryptor_->encrypt(plain, cipher);
    return cipher;
}

seal::Plaintext BGVSeal::decrypt(const seal::Ciphertext& cipher) {
    seal::Plaintext plain;
    decryptor_->decrypt(cipher, plain);
    return plain;
}

seal::Ciphertext BGVSeal::add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) {
    seal::Ciphertext result;
    evaluator_->add(ciphertext1, ciphertext2, result);
    return result;
}

seal::Ciphertext BGVSeal::add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) {
    seal::Ciphertext result;
    evaluator_->add_plain(ciphertext, plaintext, result);
    return result;
}

seal::Ciphertext BGVSeal::sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) {
    seal::Ciphertext result;
    evaluator_->sub(ciphertext1, ciphertext2, result);
    return result;
}

seal::Ciphertext BGVSeal::sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) {
    seal::Ciphertext result;
    evaluator_->sub_plain(ciphertext, plaintext, result);
    return result;
}

seal::Ciphertext BGVSeal::multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) {
    seal::Ciphertext result;
    evaluator_->multiply(ciphertext1, ciphertext2, result);
    evaluator_->relinearize_inplace(result, relin_keys_);
    return result;
}

seal::Ciphertext BGVSeal::multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) {
    seal::Ciphertext result;
    evaluator_->multiply_plain(ciphertext, plaintext, result);
    evaluator_->relinearize_inplace(result, relin_keys_);
    return result;
}

seal::Ciphertext BGVSeal::negate(const seal::Ciphertext& ciphertext) {
    seal::Ciphertext result;
    evaluator_->negate(ciphertext, result);
    return result;
}

seal::Ciphertext BGVSeal::rotate(const seal::Ciphertext& ciphertext, const int step) {
    seal::Ciphertext result;
    evaluator_->rotate_rows(ciphertext, step, galois_keys_, result);
    return result;
}

seal::Ciphertext BGVSeal::range_sum(const seal::Ciphertext& ciphertext, const int range_size) {
    seal::Ciphertext result = ciphertext;
    seal::Ciphertext rotated;
    int rotation_count = ceil(log2(range_size));

    for (int i = 0, step = 1; i < rotation_count; i++, step <<= 1) {
        evaluator_->rotate_rows(result, step, galois_keys_, rotated);
        evaluator_->add(result, rotated, result);
    }

    return result;
}