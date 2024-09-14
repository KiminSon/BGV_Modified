#include "RandomGenerator.h"
#include <ctime>

RandomGenerator::RandomGenerator() {
    random_generator_ = std::mt19937(static_cast<unsigned int>(std::time(nullptr)));
}

int64_t RandomGenerator::get_integer(int64_t lower, int64_t upper) {
    return std::uniform_int_distribution<int64_t>(lower, upper)(random_generator_);
}

int64_t RandomGenerator::get_integer(const std::vector<int64_t>& elements) {
    return elements[std::uniform_int_distribution<int64_t>(0, elements.size() - 1)(random_generator_)];
}

std::vector<int64_t> RandomGenerator::get_integer_vector(int64_t lower, int64_t upper, int vector_size) {
    std::vector<int64_t> vector(vector_size);
    for (auto& e : vector) {
        e = std::uniform_int_distribution<int64_t>(lower, upper)(random_generator_);
    }
    return vector;
}

std::vector<int64_t> RandomGenerator::get_integer_vector(const std::vector<int64_t>& elements, int vector_size) {
    std::vector<int64_t> vector(vector_size);
    for (auto& e : vector) {
        e = elements[std::uniform_int_distribution<int64_t>(0, elements.size() - 1)(random_generator_)];
    }
    return vector;
}