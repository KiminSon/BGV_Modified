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
    seal::Ciphertext cipher1 = ciphertext1;
    seal::Ciphertext cipher2 = ciphertext2;

    evaluator_->add_inplace(cipher1, cipher2);

    return cipher1;
}

seal::Ciphertext BGVSeal::add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) {
    seal::Ciphertext cipher = ciphertext;
    seal::Plaintext plain = plaintext;

    evaluator_->add_plain_inplace(cipher, plain);

    return cipher;
}

seal::Ciphertext BGVSeal::sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) {
    seal::Ciphertext cipher1 = ciphertext1;
    seal::Ciphertext cipher2 = ciphertext2;

    evaluator_->sub_inplace(cipher1, cipher2);

    return cipher1;
}

seal::Ciphertext BGVSeal::sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) {
    seal::Ciphertext cipher = ciphertext;
    seal::Plaintext plain = plaintext;

    evaluator_->sub_plain_inplace(cipher, plain);

    return cipher;
}

seal::Ciphertext BGVSeal::multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) {
    seal::Ciphertext cipher1 = ciphertext1;
    seal::Ciphertext cipher2 = ciphertext2;

    evaluator_->multiply_inplace(cipher1, cipher2);
    evaluator_->relinearize_inplace(cipher1, relin_keys_);

    return cipher1;
}

seal::Ciphertext BGVSeal::multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) {
    seal::Ciphertext cipher = ciphertext;
    seal::Plaintext plain = plaintext;

    evaluator_->multiply_plain_inplace(cipher, plain);
    evaluator_->relinearize_inplace(cipher, relin_keys_);

    return cipher;
}

seal::Ciphertext BGVSeal::negate(const seal::Ciphertext& ciphertext) {
    seal::Ciphertext cipher = ciphertext;
    evaluator_->negate_inplace(cipher);
    return cipher;
}

seal::Ciphertext BGVSeal::rotate(const seal::Ciphertext& ciphertext, const int step) {
    seal::Ciphertext cipher = ciphertext;
    evaluator_->rotate_rows_inplace(cipher, step, galois_keys_);
    return cipher;
}