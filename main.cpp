// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "modules/bgv/BGVBuilder.h"
#include "modules/bgv/BGVSeal.h"
#include "modules/random/RandomGenerator.h"
#include "modules/algorithm/Huffman.h"
#include "modules/algorithm/FFT.h"
#include "modules/simulator/MatchingSimulator.h"
#include <openssl/sha.h>
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

void binary_matching(const int32_t text_size = 2048, const int32_t pattern_size = 10) {
    cout << endl << "------------------ <Testing integer matching: text size(" << text_size << "), pattern size(" << pattern_size << ")> ------------------" << endl << endl;


    // Generate random data
    RandomGenerator rand;

    vector<int16_t> text = rand.get_integer_vector<int16_t>({ 0, 1 }, text_size);
    vector<int16_t> pattern = rand.get_integer_vector<int16_t>({ 0, 1 }, pattern_size);

    for (auto& i : rand.get_integer_vector<int32_t>(0, text.size() - pattern.size(), rand.get_integer(3, 100))) {
        for (int64_t j = 0; j < pattern.size(); j++) {
            if (i + j < text.size()) {
                text[i + j] = pattern[j];
            }
        }
    }

    cout << "Text:";
    print_vector(text, std::min(10, static_cast<int32_t>(text.size())));
    cout << "Pattern:";
    print_vector(pattern, std::min(10, static_cast<int32_t>(pattern.size())));


    //Testing
    MatchingSimulator simulator;

    {
        cout << "- hash" << endl;
        auto [time, matched] = simulator.binary_matching(text, pattern, binary_matching_type::hash);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }

    {
        cout << "- hash + rotation" << endl;
        auto [time, matched] = simulator.binary_matching(text, pattern, binary_matching_type::hash_rotation);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }
}

void integer_matching(const int32_t text_size = 2048, const int32_t pattern_size = 10, const int32_t unique_int_cnt=4) {
    cout << endl << "------------------ <Testing integer matching: text size(" << text_size << "), pattern size(" << pattern_size << ")> ------------------" << endl << endl;


    // Generate random data
    RandomGenerator rand;

    set<int16_t> int_set = rand.get_integer_set<int16_t>(
        std::numeric_limits<int16_t>::min(),
        std::numeric_limits<int16_t>::max(),
        unique_int_cnt);

    vector<int16_t> text = rand.get_integer_vector<int16_t>(vector<int16_t>(int_set.begin(), int_set.end()), text_size);
    vector<int16_t> pattern = rand.get_integer_vector<int16_t>(vector<int16_t>(int_set.begin(), int_set.end()), pattern_size);

    for (auto& i : rand.get_integer_vector<int32_t>(0, text.size() - pattern.size(), rand.get_integer(3, 100))) {
        for (int64_t j = 0; j < pattern.size(); j++) {
            if (i + j < text.size()) {
                text[i + j] = pattern[j];
            }
        }
    }

    cout << "Text:";
    print_vector(text, std::min(10, static_cast<int32_t>(text.size())));
    cout << "Pattern:";
    print_vector(pattern, std::min(10, static_cast<int32_t>(pattern.size())));

    
    //Testing
    MatchingSimulator simulator;

    {
        cout << "- hash + primitive root" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_primitive_root);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }

    {
        cout << "- hash + rotation" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_rotation);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }
}


std::vector<uint64_t> calculate_mod_frequencies_from_balanced_sets(int sub_set_size, int full_set_size) {
    std::random_device rd;
    std::mt19937 gen(rd());

    std::vector<int> full_set(full_set_size);
    std::iota(full_set.begin(), full_set.end(), 0);

    std::vector<int> set1(sub_set_size);
    std::sample(full_set.begin(), full_set.end(), set1.begin(), sub_set_size, gen);

    std::vector<int> set2(sub_set_size);
    for (int i = 0; i < sub_set_size; ++i) {
        set2[i] = (full_set_size - set1[i]) % full_set_size;
    }

    std::vector<uint64_t> mod_results(full_set_size, 0);

    for (int a : set1) {
        for (int b : set2) {
            int result = (a + b) % full_set_size;
            mod_results[result]++;
        }
    }

    return mod_results;
}

std::vector<uint64_t> calculate_mod_frequencies_from_unbalanced_sets(int sub_set_size, int full_set_size, int start_index) {
    std::vector<int> set1(sub_set_size);
    for (int i = 0; i < sub_set_size; ++i) {
        set1[i] = (start_index + i) % full_set_size;
    }

    std::vector<int> set2(sub_set_size);
    for (int i = 0; i < sub_set_size; ++i) {
        set2[i] = (full_set_size - set1[i]) % full_set_size;
    }

    std::vector<uint64_t> mod_results(full_set_size, 0);

    for (int a : set1) {
        for (int b : set2) {
            int result = (a + b) % full_set_size;
            mod_results[result]++;
        }
    }

    return mod_results;
}

std::unordered_map<uint64_t, double_t> count_ordered_permutations_mod_prob(
    const std::vector<uint64_t>& powers,
    const std::vector<uint64_t>& frequencies,
    const uint64_t min_m,
    const uint64_t max_m,
    const uint64_t p,
    const std::unordered_map<uint64_t, uint64_t>& target_mods)
{
    uint64_t total_freq = 0;
    for (const uint64_t& freq : frequencies) {
        total_freq += freq;
    }

    std::vector<std::vector<double_t>> dp(2, std::vector<double_t>(p, 0.0));
    dp[0][0] = 1.0;

    std::unordered_map<uint64_t, double_t> counts;

    for (uint64_t m = 1; m <= max_m; ++m) {
        std::cout << "  Processing m = " << m << '\n';

        auto& dp_prev = dp[(m + 1) % 2];
        auto& dp_curr = dp[m % 2];

        std::fill(dp_curr.begin(), dp_curr.end(), 0.0);

        for (uint64_t current_sum = 0; current_sum < p; ++current_sum) {
            double_t current_prob = dp_prev[current_sum];
            if (current_prob == 0.0) continue;

            for (uint64_t i = 0; i < powers.size(); ++i) {
                uint64_t power = powers[i];
                uint64_t freq = frequencies[i];
                uint64_t new_sum = (current_sum + power) % p;
                dp_curr[new_sum] += current_prob * (static_cast<double_t>(freq) / static_cast<double_t>(total_freq));
            }
        }

        if (target_mods.find(m) != target_mods.end()) {
            uint64_t target_mod = target_mods.at(m);
            double_t desired_prob = dp_curr[target_mod];

            desired_prob -= std::pow(static_cast<double>(frequencies[0]) / static_cast<double>(total_freq), m);
            counts[m] = desired_prob;
        }
    }

    return counts;
}

double_t compute_mixing_time(const vector<uint64_t>& powers, const vector<uint64_t>& frequencies, uint64_t p, double_t epsilon = 0.01) {
    uint64_t total = 0;
    for (const auto& freq : frequencies) {
        total += freq;
    }

    // 빈도수를 확률로 정규화
    vector<double_t> mu(p, 0.0);
    for (size_t i = 0; i < powers.size(); ++i) {
        mu[powers[i]] += static_cast<double_t>(frequencies[i]) / static_cast<double_t>(total);
    }

    // FFT 객체 생성 및 FFT 수행
    FFT fft;
    vector<complex<double_t>> eigenvalues = fft.compute_fft(mu);

    // 고유값의 절댓값 계산
    vector<double_t> abs_eigenvalues;
    abs_eigenvalues.reserve(p);

    for (int i = 0; i < p; ++i) {
        double_t magnitude = abs(eigenvalues[i]);
        abs_eigenvalues.push_back(magnitude);
    }

    // 두 번째로 큰 고유값 찾기 (k >=1)
    double_t second_largest_eigenvalue = 0.0;
    if (p > 1) {
        second_largest_eigenvalue = *max_element(abs_eigenvalues.begin() + 1, abs_eigenvalues.end());
    }

    // 스펙트럼 갭 계산
    double_t spectral_gap = 1.0 - second_largest_eigenvalue;

    if (spectral_gap <= 0.0) {
        throw runtime_error("스펙트럼 갭이 0 이하입니다. 랜덤 워크가 혼합되지 않습니다.");
    }

    // 혼합 시간 계산
    double_t mixing_time = log(1.0 / epsilon) / spectral_gap;

    return mixing_time;
}

void probabiity_of_root_of_unity(uint64_t unique_int_cnt, uint64_t m_begin, uint64_t m_end) {
    // random module
    RandomGenerator rand;


    // create plain modulus
    seal::Modulus plain_modulus = seal::PlainModulus::Batching(128, 28);


    // get plain modulus prime
    uint64_t prime = plain_modulus.value();
    cout << prime << '\n';


    // create nth-primitive roots using plain modulus prime
    uint64_t n = static_cast<uint64_t>(1) << static_cast<uint64_t>(ceil(log2(unique_int_cnt)));
    std::vector<uint64_t> roots;
    seal::util::try_primitive_roots(n, plain_modulus, 1, roots);
    

    // calculate powers
    std::vector<uint64_t> powers;
    uint64_t root = roots[0];
    uint64_t power = 1;

    powers.reserve(n);
    while (powers.size() < n) {
        powers.push_back(power);
        power = (power * root) % prime;
    }


    // calculate prob (병렬 처리)
    std::vector<uint64_t> original_set_frequencies;
    std::vector<uint64_t> balanced_sub_set_frequencies;
    std::vector<uint64_t> unbalanced_sub_set_frequencies;

    std::unordered_map<uint64_t, double_t> original_set;
    std::unordered_map<uint64_t, double_t> balanced_subset;
    std::unordered_map<uint64_t, double_t> unbalanced_subset;

    double_t original_set_mixing_time = 0.0;
    double_t balanced_subset_mixing_time = 0.0;
    double_t unbalanced_subset_mixing_time = 0.0;

    std::unordered_map<uint64_t, uint64_t> target_mods;
    for (uint64_t m = m_begin; m <= m_end; m++) {
        target_mods.insert({ m, m % prime });
    }
 

    // If n ans unique_int_cnt are same, we don't have to calculate subset case
    if (n == unique_int_cnt) {
        original_set_frequencies.assign(n, 1);
        original_set_mixing_time = compute_mixing_time(powers, original_set_frequencies, prime);
        original_set = count_ordered_permutations_mod_prob(powers, original_set_frequencies, m_begin, m_end, prime, target_mods);
    }
    else {   
        original_set_frequencies.assign(n, 1);
        balanced_sub_set_frequencies = calculate_mod_frequencies_from_balanced_sets(unique_int_cnt, n);
        unbalanced_sub_set_frequencies = calculate_mod_frequencies_from_unbalanced_sets(unique_int_cnt, n, 0);

        unsigned int num_cores = std::thread::hardware_concurrency();
        std::cout << "Number of CPU cores: " << num_cores << '\n';

        original_set_mixing_time = compute_mixing_time(powers, original_set_frequencies, prime);
        balanced_subset_mixing_time = compute_mixing_time(powers, balanced_sub_set_frequencies, prime);
        unbalanced_subset_mixing_time = compute_mixing_time(powers, unbalanced_sub_set_frequencies, prime);

        auto future_original_set = std::async(std::launch::async, count_ordered_permutations_mod_prob, powers, original_set_frequencies, m_begin, m_end, prime, target_mods);
        auto future_balanced_subset = std::async(std::launch::async, count_ordered_permutations_mod_prob, powers, balanced_sub_set_frequencies, m_begin, m_end, prime, target_mods);
        auto future_unbalanced_subset = std::async(std::launch::async, count_ordered_permutations_mod_prob, powers, unbalanced_sub_set_frequencies, m_begin, m_end, prime, target_mods);

        original_set = future_original_set.get();
        balanced_subset = future_balanced_subset.get();
        unbalanced_subset = future_unbalanced_subset.get();
    }


    // create text file
    std::ostringstream filename;
    filename << "unique_cnt=" << unique_int_cnt << "_n=" << n << "_p=" << prime << ".txt";
    std::ofstream out(filename.str());


    // write result
    out << "    For unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
    out << "      Primitive Root = " << root << '\n';
    out << "      Powers         = [";
    for (auto& e : powers) out << e << ", "; out << "]\n";

    out << "    For unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
    out << "      Original Set Frequencies      = [";
    for (auto& e : original_set_frequencies) out << e << ", "; out << "]\n";

    out << "      Balanced Subset Frequencies   = [";
    for (auto& e : balanced_sub_set_frequencies) out << e << ", "; out << "]\n";

    out << "      Unbalanced Subset Frequencies = [";
    for (auto& e : unbalanced_sub_set_frequencies) out << e << ", "; out << "]\n";


    out << std::fixed << std::setprecision(std::numeric_limits<double>::max_digits10);
    out << "    For unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
    out << "      Original Set Mixing Time      = " << original_set_mixing_time << '\n';
    out << "      Balanced Subset Mixing Time   = " << balanced_subset_mixing_time << '\n';
    out << "      Unbalanced Subset Mixing Time = " << unbalanced_subset_mixing_time << '\n';


    for (uint64_t m = m_begin; m <= m_end; m++) {
        auto prob_original_set = original_set[m] * 100.0;
        auto prob_balanced_subset = balanced_subset[m] * 100.0;
        auto prob_unbalanced_subset = unbalanced_subset[m] * 100.0;

        auto both_prob_original_set = prob_original_set * prob_original_set / 100.0;
        auto both_prob_balanced_subset = prob_balanced_subset * prob_balanced_subset / 100.0;
        auto both_prob_unbalanced_subset = prob_unbalanced_subset * prob_unbalanced_subset / 100.0;

        auto prob_theoretical_single_set = static_cast<double_t>(1) / (static_cast<double_t>(prime) / 100.0);
        auto prob_theoretical_both_set = pow(prob_theoretical_single_set, 2) / 100.0;

        out << "    For m = " << m << ", unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
        out << "      Convergence Single Probability     = " << prob_theoretical_single_set << '\n';
        out << "      Original Set Probability           = " << prob_original_set << '\n';
        out << "      Balanced Subset Probability        = " << prob_balanced_subset << '\n';
        out << "      Unbalanced Subset Probability      = " << prob_unbalanced_subset << '\n';

        out << "      Convergence Both Probability       = " << prob_theoretical_both_set << '\n';
        out << "      Both Original Set Probability      = " << both_prob_original_set << '\n';
        out << "      Both Balanced Subset Probability   = " << both_prob_balanced_subset << '\n';
        out << "      Both Unbalanced Subset Probability = " << both_prob_unbalanced_subset << '\n';
    }
}

void main()
{
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    probabiity_of_root_of_unity(26, 2, 100);

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    cout << "    Execution time: " << elapsed.count() << "ms" << endl << endl;

    /*for (auto& [text_size, pattern_size, unique_int_cnt] : vector<tuple<int32_t, int32_t, int32_t>>{
        {3000, 05, 26},
        {3000, 15, 26},
        {3000, 25, 26},
        {3000, 35, 26},
        {3000, 45, 26},
        {3000, 55, 26}
        })
    {
        integer_matching(3000, pattern_size, unique_int_cnt);
    }

    for (auto& [text_size, pattern_size] : vector<tuple<int32_t, int32_t>>{
        {3000, 05 },
        {3000, 15 },
        {3000, 25 },
        {3000, 35 },
        {3000, 45 },
        {3000, 55 }
        })
    {
        //binary_matching(3000, pattern_size);
    }*/
}