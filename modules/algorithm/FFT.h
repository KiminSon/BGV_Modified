#pragma once

#include <vector>
#include <complex>

class FFT {
public:
    FFT();
    ~FFT();

    std::vector<std::complex<double_t>> compute_fft(const std::vector<double_t>& input);

    std::vector<std::complex<double_t>> compute_ifft(const std::vector<std::complex<double_t>>& input);

private:
    unsigned int reverse_bits(unsigned int x, int log2n) const;

    void fft_transform(std::vector<std::complex<double_t>>& a) const;

    static constexpr double_t PI = 3.14159265358979323846;
};