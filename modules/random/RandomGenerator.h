#pragma once
#include <random>
#include <vector>
#include <set>
#include <type_traits>

class RandomGenerator {
public:
    RandomGenerator();

    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        T get_integer(T lower, T upper);

    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        T get_integer(const std::vector<T>& elements);

    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        std::vector<T> get_integer_vector(T lower, T upper, int vector_size);

    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        std::vector<T> get_integer_vector(const std::vector<T>& elements, int vector_size);

    template<typename T, typename = std::enable_if_t<
        std::is_same_v<T, int16_t> ||
        std::is_same_v<T, int32_t> ||
        std::is_same_v<T, int64_t>
        >>
        std::set<T> get_integer_set(T lower, T upper, int set_size);

private:
    std::mt19937 random_generator_;
};