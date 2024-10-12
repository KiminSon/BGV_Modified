// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "modules/bgv/BGVBuilder.h"
#include "modules/bgv/BGVSeal.h"
#include "modules/random/RandomGenerator.h"
#include "modules/algorithm/Huffman.h"
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

void main()
{
    for (auto& [text_size, pattern_size, unique_int_cnt] : vector<tuple<int32_t, int32_t, int32_t>>{
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
    }
}