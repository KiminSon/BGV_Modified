#pragma once

#include <vector>
#include <unordered_map>
#include <cstdint>
#include <string>

class Huffman {
public:
    Huffman(const std::vector<int64_t>& data);

    ~Huffman();

    Huffman(const Huffman&) = delete;

    Huffman& operator=(const Huffman&) = delete;

    std::pair<std::vector<int64_t>, std::vector<int64_t>> encode(const std::vector<int64_t>& data) const;

    std::vector<int64_t> decode(const std::vector<int64_t>& encoded_data) const;

private:
    struct Node {
        int64_t value;
        int freq;
        Node* left;
        Node* right;

        Node(int64_t v, int f) : value(v), freq(f), left(nullptr), right(nullptr) {}
        Node(int64_t v, int f, Node* l, Node* r) : value(v), freq(f), left(l), right(r) {}
    };

    struct Compare {
        bool operator()(const Node* left, const Node* right) const {
            return left->freq > right->freq;
        }
    };

    Node* root_;

    std::unordered_map<int64_t, std::pair<std::string, int>> mapping_table_;

    void create_mapping_table(Node* node, const std::string& code, int depth);

    int64_t decode_helper(Node* node, int& bit_pos, const std::vector<int64_t>& bits) const;

    void delete_tree(Node* node);
};