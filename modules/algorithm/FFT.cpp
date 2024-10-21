#include "FFT.h"
#include <cmath>

FFT::FFT() {}
FFT::~FFT() {}

unsigned int FFT::reverse_bits(unsigned int x, int log2n) const {
    unsigned int n = 0;
    for (int i = 0; i < log2n; ++i) {
        n <<= 1;
        n |= (x & 1);
        x >>= 1;
    }
    return n;
}

void FFT::fft_transform(std::vector<std::complex<double_t>>& a) const {
    int n = a.size();
    int log2n = 0;
    while ((1 << log2n) < n) log2n++;

    // 비트 반전 순서로 배열 재배열
    for (unsigned int i = 0; i < n; ++i) {
        unsigned int j = reverse_bits(i, log2n);
        if (j > i) std::swap(a[i], a[j]);
    }

    // Danielson-Lanczos 단계
    for (int s = 1; s <= log2n; ++s) {
        int m = 1 << s; // 현재 단계의 윈도우 크기
        double_t angle = -2.0 * PI / m;
        std::complex<double_t> wm(std::cos(angle), std::sin(angle));
        for (int k = 0; k < n; k += m) {
            std::complex<double_t> w(1, 0);
            for (int j = 0; j < m / 2; ++j) {
                std::complex<double_t> t = w * a[k + j + m / 2];
                std::complex<double_t> u = a[k + j];
                a[k + j] = u + t;
                a[k + j + m / 2] = u - t;
                w *= wm;
            }
        }
    }
}

std::vector<std::complex<double_t>> FFT::compute_fft(const std::vector<double_t>& input) {
    // 입력 크기 확인 및 2의 거듭제곱으로 패딩
    size_t n = 1;
    while (n < input.size()) n <<= 1;
    std::vector<std::complex<double_t>> a(n, 0.0);
    for (size_t i = 0; i < input.size(); ++i) {
        a[i] = std::complex<double_t>(input[i], 0.0);
    }

    // FFT 변환 수행
    fft_transform(a);

    return a;
}

// IFFT 수행 메서드
std::vector<std::complex<double_t>> FFT::compute_ifft(const std::vector<std::complex<double_t>>& input) {
    // 입력 크기 확인 및 2의 거듭제곱으로 패딩
    size_t n = 1;
    while (n < input.size()) n <<= 1;
    std::vector<std::complex<double_t>> a(n, 0.0);
    for (size_t i = 0; i < input.size(); ++i) {
        // IFFT를 위해 고유값의 허수부 부호를 반전시킴
        a[i] = std::complex<double_t>(input[i].real(), -input[i].imag());
    }

    // FFT 변환 수행
    fft_transform(a);

    // 결과의 허수부 부호를 다시 반전시키고 스케일링
    for (auto& c : a) {
        c = std::complex<double_t>(c.real() / n, -c.imag() / n);
    }

    return a;
}