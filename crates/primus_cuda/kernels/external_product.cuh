#pragma once

// Included after ntt.cu's arithmetic helpers in the same translation unit.
// The host binds one checked gadget layout, decomposition basis and NTT table.
// All buffers are disjoint, inputs are canonical, and count describes complete
// polynomial/ciphertext batches. n is a supported power of two; components and
// levels are positive. Every derived allocation/offset fits size_t.

namespace {

template <class T>
__device__ __forceinline__ void decompose_signed_value(
    T value, T* digits, size_t output_index, uint32_t n,
    uint32_t levels, uint32_t base_log, uint32_t drop_bits,
    T threshold, T adjustment, T q) {
    const T basis = T{1} << base_log;
    const T mask = basis - 1;
    const T half_basis = basis >> 1;
    const T modulus_minus_basis = q - basis;
    const T adjusted = value >= threshold ? value + adjustment : value;
    T carry = 0;
    if (drop_bits != 0) {
        // Round in the adjusted binary representation, rather than in the
        // original canonical residue representation.
        carry = (adjusted >> (drop_bits - 1)) & T{1};
    }
    uint32_t shift = drop_bits;
    for (uint32_t level = 0; level < levels; ++level) {
        const T temp = ((adjusted >> shift) & mask) + carry;
        // B/2 maps to -B/2; B maps to zero and still propagates a carry.
        // Carry must be derived from temp, rather than the resulting digit.
        carry = temp >= half_basis;
        digits[output_index] = temp == basis ? T{0}
            : (carry != 0 ? temp + modulus_minus_basis : temp);
        output_index += n;
        shift += base_log;
    }
}

// Input:  [batch][input component][coefficient].
// Output: [batch][input component][level][coefficient].
// Levels ascend from the lowest retained weight, matching decomposer_iter().
// threshold and adjustment reproduce ApproxSignedBasis::init_value_carry for
// the plan's explicit modulus: adjustment = 2^value_bits - q. The adjusted
// input fits value_bits, and every retained extraction shift is below it.
template <class T>
__device__ __forceinline__ void decompose_external_product(
    const T* input, T* digits, uint32_t count, uint32_t n,
    uint32_t levels, uint32_t base_log, uint32_t drop_bits,
    T threshold, T adjustment, T q) {
    const uint32_t log_n = 31 - __clz(n);
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t polynomial = index >> log_n;
        const uint32_t coefficient = static_cast<uint32_t>(index & (n - 1));
        decompose_signed_value(input[index], digits,
                               polynomial * levels * n + coefficient,
                               n, levels, base_log, drop_bits,
                               threshold, adjustment, q);
    }
}

// With m = floor(2^64 / q), rounding m down lowers p*m/2^64 by at
// most p/2^64 < 1. Thus high(p*m) is floor(p/q) or one less.
// The residual is in [0, 2q), so its low 32-bit word is exact.
__device__ __forceinline__ uint32_t external_product_mul_u32(
    uint32_t lhs, uint32_t rhs, uint32_t q, uint64_t reciprocal) {
    const uint64_t product = static_cast<uint64_t>(lhs) * rhs;
    const uint64_t quotient = high_product(product, reciprocal);
    const uint32_t remainder =
        static_cast<uint32_t>(product) - static_cast<uint32_t>(quotient) * q;
    return reduce_once(remainder, q);
}

// Digits: [batch][input component][level][NTT coefficient].
// Gadget: [batch][input component][level][output component][NTT coefficient].
// Output: [batch][output component][NTT coefficient].
// Each thread owns one complete output sum, so no atomic or cleared output is
// needed. The row loop follows CPU input-component then ascending-level order.
template <class T>
__device__ __forceinline__ void external_product(
    const T* digits, const T* gadget, T* output, uint32_t count,
    uint32_t n, uint32_t components, uint32_t levels, T q,
    uint32_t q_bits, uint64_t reciprocal) {
    const uint32_t log_n = 31 - __clz(n);
    const size_t rows = static_cast<size_t>(components) * levels;
    const size_t gadget_row_stride = static_cast<size_t>(components) * n;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t polynomial = index >> log_n;
        const size_t batch = polynomial / components;
        const size_t component = polynomial % components;
        const uint32_t coefficient = static_cast<uint32_t>(index & (n - 1));
        size_t digit_index = batch * rows * n + coefficient;
        size_t gadget_index =
            (batch * rows * components + component) * n + coefficient;
        T accumulator = 0;
        for (size_t row = 0; row < rows; ++row) {
            T product;
            if constexpr (sizeof(T) == sizeof(uint32_t)) {
                product = external_product_mul_u32(digits[digit_index], gadget[gadget_index],
                                                   q, reciprocal);
            } else {
                product = multiply_mod_u64(digits[digit_index], gadget[gadget_index],
                                           q, q_bits, reciprocal);
            }
            // Both terms are canonical. The NTT modulus headroom guarantees
            // 2q fits T, so the sum cannot overflow and one correction suffices.
            accumulator = reduce_once(accumulator + product, q);
            digit_index += n;
            gadget_index += gadget_row_stride;
        }
        output[index] = accumulator;
    }
}

}  // namespace

extern "C" __global__ void primus_decompose_u32(
    const uint32_t* input, uint32_t* digits, uint32_t count, uint32_t n,
    uint32_t levels, uint32_t base_log, uint32_t drop_bits,
    uint32_t threshold, uint32_t adjustment, uint32_t q) {
    decompose_external_product(input, digits, count, n, levels, base_log,
                               drop_bits, threshold, adjustment, q);
}

extern "C" __global__ void primus_decompose_u64(
    const uint64_t* input, uint64_t* digits, uint32_t count, uint32_t n,
    uint32_t levels, uint32_t base_log, uint32_t drop_bits,
    uint64_t threshold, uint64_t adjustment, uint64_t q) {
    decompose_external_product(input, digits, count, n, levels, base_log,
                               drop_bits, threshold, adjustment, q);
}

extern "C" __global__ void primus_external_product_u32(
    const uint32_t* digits, const uint32_t* gadget, uint32_t* output,
    uint32_t count, uint32_t n, uint32_t components, uint32_t levels, uint32_t q,
    uint64_t reciprocal) {
    external_product(digits, gadget, output, count, n, components, levels, q, 0, reciprocal);
}

extern "C" __global__ void primus_external_product_u64(
    const uint64_t* digits, const uint64_t* gadget, uint64_t* output,
    uint32_t count, uint32_t n, uint32_t components, uint32_t levels, uint64_t q,
    uint32_t q_bits, uint64_t reciprocal) {
    external_product(digits, gadget, output, count, n, components, levels, q,
                      q_bits, reciprocal);
}
