#include "MatchingSimulator.h"
#include "seal/seal.h"
#include "../bgv/BGVBuilder.h"
#include "../bgv/BGVSeal.h"
#include "../random/RandomGenerator.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <unordered_map>
#include <chrono>

std::pair<std::vector<int64_t>, std::vector<int64_t>> MatchingSimulator::convert_binary_data(const std::vector<int16_t> &text, const std::vector<int16_t> &pattern) {
    auto convert = [](const std::vector<int16_t>& binary_data) {
        std::vector<int64_t> new_data;

        new_data.reserve(binary_data.size());

        for (auto e : binary_data) {
            new_data.push_back(e == 0 ? -1 : 1);
        }
       
        return new_data;
    };

    return { convert(text), convert(pattern) };
}

std::pair<std::vector<int64_t>, std::vector<int64_t>> MatchingSimulator::convert_integer_data(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern) {
    std::unordered_map<int16_t, int64_t> mapping;
    int32_t next_value = 1;

    auto build_map = [&mapping, &next_value](const std::vector<int16_t>& data) {
        for (auto e : data) {
            if (mapping.find(e) == mapping.end()) {
                mapping.insert({ e, next_value++ });
            }
        }
    };

    auto convert = [&mapping](const std::vector<int16_t>& integer_data) {
        std::vector<int64_t> new_data;

        new_data.reserve(integer_data.size());

        for (auto e : integer_data) {
            new_data.push_back(mapping.at(e));
        }

        return new_data;
    };

    build_map(text);
    build_map(pattern);

    return { convert(text), convert(pattern) };
}

std::pair<double, std::vector<int>> MatchingSimulator::binary_matching(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern, const binary_matching_type matching_type) {
    auto [new_text, new_pattern] = convert_binary_data(text, pattern);
    std::vector<int> matched;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    switch (matching_type)
    {
    case binary_matching_type::hash: {
        binary_matching_hash(new_text, new_pattern, matched);
        break;
    }
    case binary_matching_type::hash_rotation: {
        binary_matching_hash_rotation(new_text, new_pattern, matched);
        break;
    }
    default:
        throw std::invalid_argument("Unsupported matching type");
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    return { elapsed.count(), matched };
}

std::pair<double, std::vector<int>> MatchingSimulator::integer_matching(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern, const integer_matching_type matching_type) {
    auto [new_text, new_pattern] = convert_integer_data(text, pattern);
    std::vector<int> matched;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    switch (matching_type)
    {
    case integer_matching_type::hash_primitive_root: {
        integer_matching_hash_primitive_root(new_text, new_pattern, matched);
        break;
    }
    case integer_matching_type::hash_rotation: {
        integer_matching_hash_rotation(new_text, new_pattern, matched);
        break;
    }
    default:
        throw std::invalid_argument("Unsupported matching type");
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    return { elapsed.count(), matched };
}

std::string MatchingSimulator::sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void MatchingSimulator::binary_matching_hash(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int>& matched) {
    // random module
    RandomGenerator rand;


    // create bgv
    SEALHelper& bgv = SEALBuilder(seal::scheme_type::bgv, seal::sec_level_type::tc128, 8192, { 40, 30, 30, 30, 40 }, 31, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    // get plain modulus prime
    int64_t prime = bgv.plain_modulus_prime();


    // create Bob function
    auto bob = [&](seal::Ciphertext& pattern_enc) {
        seal::Plaintext text_pln;
        std::reverse(text.begin(), text.end());
        text_pln = bgv.encode(text);

        // calculate: (t * p - n) * a + r
        std::vector<seal::Ciphertext> result_enc(2);
        std::vector<std::string> hash(text.size(), "");

        for (int32_t i = 0; i < 2; i++) {
            auto a = rand.get_integer<int64_t>(1, prime / 2) * rand.get_integer<int64_t>({ -1, 1 });
            auto r = rand.get_integer_vector<int64_t>(-prime / 2, prime / 2, text.size());

            for (int32_t j = 0; j < r.size(); j++) {
                hash[j] += sha256(std::to_string(r[j]));
            }

            result_enc[i] = bgv.multiply(pattern_enc, text_pln);
            result_enc[i] = bgv.sub(result_enc[i], bgv.encode(std::vector<int64_t>(text.size(), pattern.size())));
            result_enc[i] = bgv.multiply(result_enc[i], bgv.encode(std::vector<int64_t>(1, a)));
            result_enc[i] = bgv.add(result_enc[i], bgv.encode(r));
        }

        return std::make_pair(result_enc, hash);
    };


    // create Alice function
    auto alice = [&]() {
        seal::Ciphertext pattern_enc;
        pattern_enc = bgv.encrypt(bgv.encode(pattern));

        // send to bob
        auto [result_enc, hash] = bob(pattern_enc);

        // analyzing result
        matched.clear();
        std::vector<std::vector<int64_t>> result(2);

        for (int32_t i = 0; i < 2; i++) {
            result[i] = bgv.decode(bgv.decrypt(result_enc[i]));
        }

        for (int32_t i = 0; i < text.size(); i++) {
            std::string hashing_result = "";

            for (int32_t j = 0; j < 2; j++) {
                hashing_result += sha256(std::to_string(result[j][i]));
            }

            if (hashing_result == hash[i]) {
                matched.push_back(static_cast<int>(text.size()) - i - 1);
            }
        }
    };

    alice();
}

void MatchingSimulator::binary_matching_hash_rotation(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int>& matched) {
    // random module
    RandomGenerator rand;


    // create bgv
    SEALHelper& bgv = SEALBuilder(seal::scheme_type::bgv, seal::sec_level_type::tc128, 8192, { 40, 30, 30, 30, 40 }, 31, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    // get plain modulus prime
    int64_t prime = bgv.plain_modulus_prime();


    // create Bob function
    auto bob = [&](seal::Ciphertext& pattern_enc, int32_t pattern_size) {
        std::vector<int64_t> text_sav(text);
        std::vector<std::vector<seal::Ciphertext>> result_enc(pattern_size, std::vector<seal::Ciphertext>(2));
        std::vector<std::vector<std::string>> hash(pattern_size, std::vector<std::string>(text.size(), ""));

        for (int64_t rot = 0; rot < pattern_size; rot++) {
            for (int32_t i = 0; i < text.size(); i++) {
                text[i] = text_sav[(i + rot) % text.size()];
            }
            seal::Plaintext text_pln = bgv.encode(text);

            for (int32_t i = 0; i < 2; i++) {
                auto p = rand.get_integer_vector<int64_t>(-prime / 2, prime / 2, pattern_size);
                auto a = rand.get_integer<int64_t>(1, prime / 2) * rand.get_integer<int64_t>({ -1, 1 });
                auto r = rand.get_integer_vector<int64_t>(-prime / 2, prime / 2, text.size());

                for (int32_t j = 0; j < r.size(); j++) {
                    hash[rot][j] += sha256(std::to_string(r[j]));
                }

                result_enc[rot][i] = bgv.sub(pattern_enc, text_pln);
                result_enc[rot][i] = bgv.multiply(result_enc[rot][i], bgv.encode(p));
                result_enc[rot][i] = bgv.multiply(result_enc[rot][i], bgv.encode(std::vector<int64_t>(1, a)));
                result_enc[rot][i] = bgv.add(result_enc[rot][i], bgv.encode(r));
            }
        }

        return std::make_pair(result_enc, hash);
    };

    // create Alice function
    auto alice = [&]() {
        seal::Ciphertext pattern_enc;
        std::vector<int64_t> pattern_sav(pattern);
        int32_t pattern_size = pattern_sav.size();

        pattern.reserve(text.size());
        while (pattern.size() + pattern_sav.size() <= text.size()) {
            pattern.insert(pattern.end(), pattern_sav.begin(), pattern_sav.end());
        }

        pattern_enc = bgv.encrypt(bgv.encode(pattern));

        // send to bob
        auto [result_enc, hash] = bob(pattern_enc, pattern_size);

        // analyzing result
        matched.clear();

        for (int32_t rot = 0; rot < pattern_size; rot++) {
            std::vector<std::vector<int64_t>> result(2);

            for (int32_t i = 0; i < 2; i++) {
                result[i] = bgv.decode(bgv.decrypt(result_enc[rot][i]));
            }

            for (int32_t i = static_cast<int32_t>(pattern_size) - 1; i < static_cast<int32_t>(text.size()) - rot; i += pattern_size) {
                std::string hashing_result = "";

                for (int32_t j = 0; j < 2; j++) {
                    hashing_result += sha256(std::to_string(result[j][i]));
                }

                if (hashing_result == hash[rot][i]) {
                    matched.push_back(static_cast<int64_t>(i) - pattern_size + 1 + rot);
                }
            }
        }
    };

    alice();
}

void MatchingSimulator::integer_matching_hash_primitive_root(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int>& matched) {
    // random module
    RandomGenerator rand;


    // create bgv
    SEALHelper& bgv = SEALBuilder(seal::scheme_type::bgv, seal::sec_level_type::tc128, 8192, { 40, 30, 30, 30, 40 }, 31, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    // get plain modulus prime
    int64_t prime = bgv.plain_modulus_prime();


    // create nth-primitive roots using plain modulus prime
    int64_t unique_int_cnt = std::max(
        *std::max_element(text.begin(), text.end()),
        *std::max_element(pattern.begin(), pattern.end())
    );

    int64_t n = static_cast<int64_t>(1) << static_cast<int64_t>(ceil(log2(unique_int_cnt)));
    std::vector<uint64_t> roots = bgv.plain_modulus_roots(n, 2);

    std::vector<std::vector<int64_t>> powers(2);
    std::vector<std::unordered_map<int64_t, int>> int2power_map(2);


    // mapping
    for (int32_t i = 0; i < 2; i++) {
        uint64_t root = roots[i];
        uint64_t power = 1;
        uint64_t h_prime = static_cast<uint64_t>(prime / 2);

        powers[i].reserve(n);

        while (powers[i].size() < n) {
            powers[i].push_back(power > h_prime ? power - prime : power);
            power = (power * root) % prime;
        }

        int32_t int_value = 1;
        for (auto& degree : rand.get_integer_set<int>(0, n - 1, unique_int_cnt)) {
            int2power_map[i].insert({ int_value++, degree });
        }
    }


    // create Bob function
    auto bob = [&](std::vector<seal::Ciphertext>& pattern_enc) {
        std::vector<seal::Plaintext> text_pln(2);

        for (int32_t i = 0; i < 2; i++) {
            for (auto& e : text) {
                e = powers[i][int2power_map[i][e]];
            }
            std::reverse(text.begin(), text.end());
            text_pln[i] = bgv.encode(text);
        }

        // calculate: (t * p - n) * a + r
        std::vector<seal::Ciphertext> result_enc(2);
        std::vector<std::string> hash(text.size(), "");

        for (int32_t i = 0; i < 2; i++) {
            auto a = rand.get_integer<int64_t>(1, prime / 2) * rand.get_integer<int64_t>({ -1, 1 });
            auto r = rand.get_integer_vector<int64_t>(-prime / 2, prime / 2, text.size());

            for (int32_t j = 0; j < r.size(); j++) {
                hash[j] += sha256(std::to_string(r[j]));
            }

            result_enc[i] = bgv.multiply(pattern_enc[i], text_pln[i]);
            result_enc[i] = bgv.sub(result_enc[i], bgv.encode(std::vector<int64_t>(text.size(), pattern.size())));
            result_enc[i] = bgv.multiply(result_enc[i], bgv.encode(std::vector<int64_t>(1, a)));
            result_enc[i] = bgv.add(result_enc[i], bgv.encode(r));
        }

        return std::make_pair(result_enc, hash);
    };


    // create Alice function
    auto alice = [&]() {
        std::vector<seal::Ciphertext> pattern_enc(2);

        for (int32_t i = 0; i < 2; i++) {
            for (auto& e : pattern) {
                e = powers[i][(n - int2power_map[i][e]) % n];
            }
            pattern_enc[i] = bgv.encrypt(bgv.encode(pattern));
        }

        // send to bob
        auto [result_enc, hash] = bob(pattern_enc);

        // analyzing result
        matched.clear();
        std::vector<std::vector<int64_t>> result(2);

        for (int32_t i = 0; i < 2; i++) {
            result[i] = bgv.decode(bgv.decrypt(result_enc[i]));
        }

        for (int32_t i = 0; i < text.size(); i++) {
            std::string hashing_result = "";

            for (int32_t j = 0; j < 2; j++) {
                hashing_result += sha256(std::to_string(result[j][i]));
            }

            if (hashing_result == hash[i]) {
                matched.push_back(static_cast<int>(text.size()) - i - 1);
            }
        }
    };

    alice();
}

void MatchingSimulator::integer_matching_hash_rotation(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int>& matched) {
    // random module
    RandomGenerator rand;


    // create bgv
    SEALHelper& bgv = SEALBuilder(seal::scheme_type::bgv, seal::sec_level_type::tc128, 8192, { 40, 30, 30, 30, 40 }, 31, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();


    // get plain modulus prime
    int64_t prime = bgv.plain_modulus_prime();


    // create Bob function
    auto bob = [&](seal::Ciphertext& pattern_enc, int32_t pattern_size) {
        std::vector<int64_t> text_sav(text);
        std::vector<std::vector<seal::Ciphertext>> result_enc(pattern_size, std::vector<seal::Ciphertext>(2));
        std::vector<std::vector<std::string>> hash(pattern_size, std::vector<std::string>(text.size(), ""));

        for (int64_t rot = 0; rot < pattern_size; rot++) {
            for (int32_t i = 0; i < text.size(); i++) {
                text[i] = text_sav[(i + rot) % text.size()];
            }
            seal::Plaintext text_pln = bgv.encode(text);

            for (int32_t i = 0; i < 2; i++) {
                auto p = rand.get_integer_vector<int64_t>(-prime / 2, prime / 2, pattern_size);
                auto a = rand.get_integer<int64_t>(1, prime / 2) * rand.get_integer<int64_t>({ -1, 1 });
                auto r = rand.get_integer_vector<int64_t>(-prime / 2, prime / 2, text.size());

                for (int32_t j = 0; j < r.size(); j++) {
                    hash[rot][j] += sha256(std::to_string(r[j]));
                }

                result_enc[rot][i] = bgv.sub(pattern_enc, text_pln);
                result_enc[rot][i] = bgv.multiply(result_enc[rot][i], bgv.encode(p));
                result_enc[rot][i] = bgv.multiply(result_enc[rot][i], bgv.encode(std::vector<int64_t>(1, a)));
                result_enc[rot][i] = bgv.add(result_enc[rot][i], bgv.encode(r));
            }
        }

        return std::make_pair(result_enc, hash);
    };

    // create Alice function
    auto alice = [&]() {
        seal::Ciphertext pattern_enc;
        std::vector<int64_t> pattern_sav(pattern);
        int32_t pattern_size = pattern_sav.size();

        pattern.reserve(text.size());
        while (pattern.size() + pattern_sav.size() <= text.size()) {
            pattern.insert(pattern.end(), pattern_sav.begin(), pattern_sav.end());
        }

        pattern_enc = bgv.encrypt(bgv.encode(pattern));

        // send to bob
        auto [result_enc, hash] = bob(pattern_enc, pattern_size);

        // analyzing result
        matched.clear();

        for (int32_t rot = 0; rot < pattern_size; rot++) {
            std::vector<std::vector<int64_t>> result(2);

            for (int32_t i = 0; i < 2; i++) {
                result[i] = bgv.decode(bgv.decrypt(result_enc[rot][i]));
            }

            for (int32_t i = static_cast<int32_t>(pattern_size) - 1; i < static_cast<int32_t>(text.size()) - rot; i += pattern_size) {
                std::string hashing_result = "";

                for (int32_t j = 0; j < 2; j++) {
                    hashing_result += sha256(std::to_string(result[j][i]));
                }

                if (hashing_result == hash[rot][i]) {
                    matched.push_back(static_cast<int64_t>(i) - pattern_size + 1 + rot);
                }
            }
        }
    };

    alice();
}