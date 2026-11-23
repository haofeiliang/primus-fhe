#pragma once

#include "external_product.cuh"

// Included after the arithmetic helpers in ntt.cu. The host binds complete
// disjoint GLWE batches, canonical residues, and one resident key using the
// plan's exact roots and signed decomposition. All flattened offsets fit size_t.

namespace {

// Input:  [batch][input mask polynomial, body][coefficient].
// Digits: [batch][input mask polynomial][level][coefficient].
// count excludes bodies, so they are neither decomposed nor transformed.
template <class T>
__device__ __forceinline__ void key_switch_decompose(
    const T* input, T* digits, uint32_t count, uint32_t n,
    uint32_t input_dimension, uint32_t levels, uint32_t base_log,
    uint32_t drop_bits, T threshold, T adjustment, T q) {
    const uint32_t log_n = 31 - __clz(n);
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t polynomial = index >> log_n;
        const size_t batch = polynomial / input_dimension;
        const uint32_t coefficient = static_cast<uint32_t>(index & (n - 1));
        // Each preceding lane contributes one skipped body polynomial.
        const T value = input[index + batch * n];
        decompose_signed_value(value, digits,
                               polynomial * levels * n + coefficient,
                               n, levels, base_log, drop_bits,
                               threshold, adjustment, q);
    }
}

// Key:    [input mask polynomial][level][output component][NTT coefficient].
// Output: [batch][output component][NTT coefficient].
// The same resident key is shared by every lane. Negating the exact modular sum
// before the inverse transform is equivalent to CPU's coefficient-domain
// negation, and leaves only body addition after that transform.
template <class T>
__device__ __forceinline__ void key_switch_accumulate(
    const T* digits, const T* key, T* output, uint32_t count,
    uint32_t n, uint32_t input_dimension, uint32_t output_components,
    uint32_t levels, T q, uint32_t q_bits, uint64_t reciprocal) {
    const uint32_t log_n = 31 - __clz(n);
    const size_t rows = static_cast<size_t>(input_dimension) * levels;
    const size_t key_row_stride = static_cast<size_t>(output_components) * n;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t polynomial = index >> log_n;
        const size_t batch = polynomial / output_components;
        const size_t component = polynomial % output_components;
        const uint32_t coefficient = static_cast<uint32_t>(index & (n - 1));
        size_t digit_index = batch * rows * n + coefficient;
        size_t key_index = component * n + coefficient;
        T accumulator = 0;
        for (size_t row = 0; row < rows; ++row) {
            T product;
            if constexpr (sizeof(T) == sizeof(uint32_t)) {
                product = multiply_mod_u32(digits[digit_index], key[key_index], q);
            } else {
                product = multiply_mod_u64(digits[digit_index], key[key_index],
                                           q, q_bits, reciprocal);
            }
            // Canonical terms sum below 2q, within the NTT word headroom.
            accumulator = reduce_once(accumulator + product, q);
            digit_index += n;
            key_index += key_row_stride;
        }
        output[index] = accumulator == 0 ? T{0} : q - accumulator;
    }
}

template <class T>
__device__ __forceinline__ void key_switch_add_body(
    const T* input, T* output, uint32_t count, uint32_t n,
    uint32_t input_dimension, uint32_t output_components, T q) {
    const uint32_t log_n = 31 - __clz(n);
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t batch = index >> log_n;
        const uint32_t coefficient = static_cast<uint32_t>(index & (n - 1));
        const size_t input_body =
            (batch * (static_cast<size_t>(input_dimension) + 1) + input_dimension) * n;
        const size_t output_body =
            (batch * output_components + output_components - 1) * n;
        output[output_body + coefficient] = reduce_once(
            output[output_body + coefficient] + input[input_body + coefficient], q);
    }
}

}  // namespace

#define PRIMUS_KEY_SWITCH_COMMON(WORD, SUFFIX)                                      \
extern "C" __global__ void primus_key_switch_decompose_##SUFFIX(                   \
    const WORD* input, WORD* digits, uint32_t count, uint32_t n,                   \
    uint32_t input_dimension, uint32_t levels, uint32_t base_log,                  \
    uint32_t drop_bits, WORD threshold, WORD adjustment, WORD q) {                \
    key_switch_decompose(input, digits, count, n, input_dimension, levels,        \
                         base_log, drop_bits, threshold, adjustment, q);          \
}                                                                                \
extern "C" __global__ void primus_key_switch_add_body_##SUFFIX(                    \
    const WORD* input, WORD* output, uint32_t count, uint32_t n,                   \
    uint32_t input_dimension, uint32_t output_components, WORD q) {               \
    key_switch_add_body(input, output, count, n, input_dimension,                 \
                        output_components, q);                                   \
}

PRIMUS_KEY_SWITCH_COMMON(uint32_t, u32)
PRIMUS_KEY_SWITCH_COMMON(uint64_t, u64)
#undef PRIMUS_KEY_SWITCH_COMMON

extern "C" __global__ void primus_key_switch_accumulate_u32(
    const uint32_t* digits, const uint32_t* key, uint32_t* output, uint32_t count,
    uint32_t n, uint32_t input_dimension, uint32_t output_components,
    uint32_t levels, uint32_t q) {
    key_switch_accumulate(digits, key, output, count, n, input_dimension,
                          output_components, levels, q, 0, 0);
}

extern "C" __global__ void primus_key_switch_accumulate_u64(
    const uint64_t* digits, const uint64_t* key, uint64_t* output, uint32_t count,
    uint32_t n, uint32_t input_dimension, uint32_t output_components,
    uint32_t levels, uint64_t q, uint32_t q_bits, uint64_t reciprocal) {
    key_switch_accumulate(digits, key, output, count, n, input_dimension,
                          output_components, levels, q, q_bits, reciprocal);
}
