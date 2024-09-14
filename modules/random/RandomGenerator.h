#pragma once
#include <random>
#include <vector>

class RandomGenerator {
public:
    RandomGenerator();

    int64_t get_integer(int64_t lower, int64_t upper);

    int64_t get_integer(const std::vector<int64_t>& elements);

    std::vector<int64_t> get_integer_vector(int64_t lower, int64_t upper, int vector_size);

    std::vector<int64_t> get_integer_vector(const std::vector<int64_t>& elements, int vector_size);

private:
    std::mt19937 random_generator_;
};