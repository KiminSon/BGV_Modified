#include "RandomGenerator.h"
#include <ctime>

RandomGenerator::RandomGenerator() {
    random_generator_ = std::mt19937(static_cast<unsigned int>(std::time(nullptr)));
}

template<typename T, typename>
T RandomGenerator::get_integer(T lower, T upper) {
    return std::uniform_int_distribution<T>(lower, upper)(random_generator_);
}

template<typename T, typename>
T RandomGenerator::get_integer(const std::vector<T>& elements) {
    return elements[std::uniform_int_distribution<size_t>(0, elements.size() - 1)(random_generator_)];
}

template<typename T, typename>
std::vector<T> RandomGenerator::get_integer_vector(T lower, T upper, int vector_size) {
    std::vector<T> vector(vector_size);
    for (auto& e : vector) {
        e = std::uniform_int_distribution<T>(lower, upper)(random_generator_);
    }
    return vector;
}

template<typename T, typename>
std::vector<T> RandomGenerator::get_integer_vector(const std::vector<T>& elements, int vector_size) {
    std::vector<T> vector(vector_size);
    for (auto& e : vector) {
        e = elements[std::uniform_int_distribution<size_t>(0, elements.size() - 1)(random_generator_)];
    }
    return vector;
}

template<typename T, typename>
std::set<T> RandomGenerator::get_integer_set(T lower, T upper, int set_size) {
    std::set<T> result_set;
    while (result_set.size() < set_size) {
        T random_value = std::uniform_int_distribution<T>(lower, upper)(random_generator_);
        result_set.insert(random_value);
    }
    return result_set;
}

template int16_t RandomGenerator::get_integer(int16_t, int16_t);
template int32_t RandomGenerator::get_integer(int32_t, int32_t);
template int64_t RandomGenerator::get_integer(int64_t, int64_t);

template int16_t RandomGenerator::get_integer(const std::vector<int16_t>&);
template int32_t RandomGenerator::get_integer(const std::vector<int32_t>&);
template int64_t RandomGenerator::get_integer(const std::vector<int64_t>&);

template std::vector<int16_t> RandomGenerator::get_integer_vector(int16_t, int16_t, int);
template std::vector<int32_t> RandomGenerator::get_integer_vector(int32_t, int32_t, int);
template std::vector<int64_t> RandomGenerator::get_integer_vector(int64_t, int64_t, int);

template std::vector<int16_t> RandomGenerator::get_integer_vector(const std::vector<int16_t>&, int);
template std::vector<int32_t> RandomGenerator::get_integer_vector(const std::vector<int32_t>&, int);
template std::vector<int64_t> RandomGenerator::get_integer_vector(const std::vector<int64_t>&, int);

template std::set<int16_t> RandomGenerator::get_integer_set(int16_t, int16_t, int);
template std::set<int32_t> RandomGenerator::get_integer_set(int32_t, int32_t, int);
template std::set<int64_t> RandomGenerator::get_integer_set(int64_t, int64_t, int);