// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "modules/bgv/BGVBuilder.h"
#include "modules/bgv/BGVSeal.h"
#include "modules/random/RandomGenerator.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <chrono>
#include <thread>
#include <set>
#include <limits>

#include <fstream>
#include <sstream>
#include <iomanip> 
#include <future>
#include <thread>

using namespace std;
using namespace seal;

void main()
{
    // random module
    RandomGenerator rand;

    // set modulus degree
    int64_t modulus_degree = 16384;

    /*
    create bfv.
    BFV스킴 사용
    최대 비트 128비트로 설정
    modulus_degree는 16384로 설정
    q값 설정
    p값 설정
    ntt사용
    아래는 키 세팅
    */ 
    SEALHelper& bfv = SEALBuilder(scheme_type::bfv, sec_level_type::tc128, modulus_degree, { 40, 30, 30, 30, 30, 30, 30, 30, 30, 30, 40 }, 31, true)
        .create_secret_key()
        .create_public_key()
        .create_galois_keys({ 1, 2, 4, 8, 16 })
        .create_relin_keys()
        .build();

    // get plain modulus prime
    int64_t prime = bfv.plain_modulus_prime();

    // input data
    set<int64_t> s1 = rand.get_integer_set<int64_t>(1, 20, 10);
    vector<int64_t> users(s1.begin(), s1.end());
    cout << "users = {";
    for (size_t i = 0; i < users.size(); ++i) {
        cout << users[i];
        if (i != users.size() - 1) {
            cout << ", ";
        }
    }
    cout << "}\n";

    set<int64_t> s2 = rand.get_integer_set<int64_t>(1, 40, 20);
    vector<int64_t> sns_users(s2.begin(), s2.end());
    cout << "sns_users = {";
    for (size_t i = 0; i < sns_users.size(); ++i) {
        cout << sns_users[i];
        if (i != sns_users.size() - 1) {
            cout << ", ";
        }
    }
    cout << "}\n";

    // 연산을 위한 vector size 조정 1에서 0을 빼면 1이 나오기 때문에 rotate 할 때 문제가 생기지 않음
    vector<int64_t> adjusted_users(modulus_degree, 1);
    vector<int64_t> adjusted_sns_users(modulus_degree, 0);
    int64_t adjusted_vector_size = pow(2, ceil(log2(sns_users.size())));

    /*
    user가 2, 3이고 sns_user가 1,3,4,5,6이면
    2, 2, 2, 2, 2, 1, 1, 1, 3, 3, 3, 3, 3, 1, 1, 1
    1, 3, 4, 5, 6, 0, 0, 0, 0, 3, 4, 5, 6, 0, 0, 0
    이런 식으로 저장
    후에 한 번에 뺀 다음에 따로따로 rotate를 함
    */
    for (int64_t i = 0; i < users.size(); i++) {
        for (int64_t j = 0; j < sns_users.size(); j++) {
            adjusted_users[i * adjusted_vector_size + j] = users[i];
            adjusted_sns_users[i * adjusted_vector_size + j] = sns_users[j];
        }
    }

    // define calculate function
    auto range_multiply = [&bfv](const seal::Ciphertext& ciphertext, const int range_size) {
        Ciphertext result = ciphertext;
        Ciphertext rotated;
        int rotation_count = ceil(log2(range_size));

        for (int i = 0, step = 1; i < rotation_count; i++, step <<= 1) {
            rotated = bfv.rotate(result, step);
            result = bfv.multiply(result, rotated);
        }

        return result;
    };

    //user는 암호문으로, sns user는 평문으로 저장
    Ciphertext user_enc = bfv.encrypt(bfv.encode(adjusted_users));
    Plaintext sns_users_pln = bfv.encode(adjusted_sns_users);

    // user - sns user를 한 뒤 rotate 실행
    Ciphertext result_enc = bfv.sub(user_enc, sns_users_pln);
    result_enc = range_multiply(result_enc, sns_users.size());

    // -p/2 ~ p/2 범위의 random vector을 생성 후 결과에 곱함
    vector<int64_t> r = rand.get_integer_vector<int64_t>(1, prime / 2, modulus_degree);
    for (auto& e : r) {
       e *= rand.get_integer<int64_t>({ -1, 1 });
    }
    result_enc = bfv.multiply(result_enc, bfv.encode(r));

    // decrypt result and print
    vector<int64_t> result = bfv.decode(bfv.decrypt(result_enc));
    for (int64_t i = 0; i < users.size(); i++) {
        cout << i << ") user id: " << users[i] << ", result: " << result[i * adjusted_vector_size] << '\n';
    }
}