#pragma once
#include <vector>
#include <string>

enum class binary_matching_type : int8_t {
	hash,
	hash_rotation,
};

enum class integer_matching_type : int8_t {
	hash_primitive_root,
	hash_rotation,
};

class MatchingSimulator {
public:
	std::pair<double, std::vector<int>> binary_matching(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern, const binary_matching_type matching_type);

	std::pair<double, std::vector<int>> integer_matching(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern, const integer_matching_type matching_type);

private:
	std::pair<std::vector<int64_t>, std::vector<int64_t>> convert_binary_data(const std::vector<int16_t> &text, const std::vector<int16_t> &pattern);

	std::pair<std::vector<int64_t>, std::vector<int64_t>> convert_integer_data(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern);

	std::string sha256(const std::string& str);

	void binary_matching_hash(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int>& matched);

	void binary_matching_hash_rotation(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int>& matched);

	void integer_matching_hash_primitive_root(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int> &matched);

	void integer_matching_hash_rotation(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int>& matched);
};