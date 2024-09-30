#include "Huffman.h"
#include <queue>
#include <stdexcept>
#include <iostream>

Huffman::Huffman(const std::vector<int64_t>& data) {
    if (data.empty()) {
        root_ = nullptr;
        return;
    }

    std::unordered_map<int64_t, int> frequencies;
    for (const int64_t& val : data) {
        frequencies[val]++;
    }

    std::priority_queue<Node*, std::vector<Node*>, Compare> pq;
    for (auto& [value, freq] : frequencies) {
        pq.push(new Node(value, freq));
    }

    int64_t internal_node_id = -1;

    while (pq.size() > 1) {
        Node* left = pq.top();
        pq.pop();
        Node* right = pq.top();
        pq.pop();
        int sum = left->freq + right->freq;
        pq.push(new Node(internal_node_id--, sum, left, right));
    }

    root_ = pq.top();
    pq.pop();

    create_mapping_table(root_, "", 0);

    for (auto& e : mapping_table_) {
        std::cout << e.first<<' '<< e.second.first << '\n';
    }
    std::cout << '\n';
}

Huffman::~Huffman() {
    delete_tree(root_);
}

std::pair<std::vector<int64_t>, std::vector<int64_t>> Huffman::encode(const std::vector<int64_t>& data) const {
    std::vector<int64_t> encoded_data;
    std::vector<int64_t> value_location;

    encoded_data.reserve(data.size() * 2);
    value_location.reserve(data.size());

    if (data.empty() || !root_) return { encoded_data, value_location };

    int current_bit_pos = 0;

    for (const int64_t& val : data) {
        value_location.push_back(current_bit_pos);
        auto it = mapping_table_.find(val);
        if (it == mapping_table_.end()) {
            throw std::invalid_argument("인코딩할 수 없는 값이 포함되어 있습니다.");
        }

        const std::string& code = it->second.first;
        for (auto& e : code) encoded_data.push_back(e == '1');
        current_bit_pos += code.size();
    }

    return { encoded_data, value_location };
}

std::vector<int64_t> Huffman::decode(const std::vector<int64_t>& encoded_data) const {
    std::vector<int64_t> decoded_data;
    if (!root_) return decoded_data;

    if (!root_->left && !root_->right) {
        int num_symbols = encoded_data.size();
        decoded_data.reserve(num_symbols);
        for (int i = 0; i < num_symbols; ++i) {
            decoded_data.push_back(root_->value);
        }
        return decoded_data;
    }

    int bit_pos = -1;
    try {
        while (bit_pos < static_cast<int>(encoded_data.size()) - 1) {
            decoded_data.push_back(decode_helper(root_, bit_pos, encoded_data));
        }
    }
    catch (const std::invalid_argument& e) {
        throw;
    }

    return decoded_data;
}

void Huffman::create_mapping_table(Node* node, const std::string& code, int depth) {
    if (!node) return;

    if (!node->left && !node->right) {
        if (depth == 0) {
            mapping_table_[node->value] = { "0", 1 };
        }
        else {
            mapping_table_[node->value] = { code, depth };
        }
        return;
    }

    if (node->left) {
        create_mapping_table(node->left, code + "0", depth + 1);
    }

    if (node->right) {
        create_mapping_table(node->right, code + "1", depth + 1);
    }
}

int64_t Huffman::decode_helper(Node* node, int& bit_pos, const std::vector<int64_t>& bits) const {
    if (!node) {
        throw std::invalid_argument("디코딩 중에 null 노드에 도달했습니다.");
    }

    if (!node->left && !node->right) {
        return node->value;
    }

    bit_pos++;
    if (bit_pos >= static_cast<int>(bits.size())) {
        throw std::invalid_argument("디코딩 중 데이터가 예상보다 짧습니다.");
    }

    if (bits[bit_pos] == '0') {
        return decode_helper(node->left, bit_pos, bits);
    }
    else {
        return decode_helper(node->right, bit_pos, bits);
    }
}

void Huffman::delete_tree(Node* node) {
    if (!node) return;
    delete_tree(node->left);
    delete_tree(node->right);
    delete node;
}
