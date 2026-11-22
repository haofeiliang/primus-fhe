#pragma once

#include <stddef.h>
#include <stdint.h>

namespace {

struct MonomialPreimage {
    uint32_t source;
    bool negate;
};

// For power-of-two n and local < n, these bits interpret any u32 degree
// modulo 2n. The source stays inside the same length-n polynomial; crossing
// X^n flips the sign, including the extra flip from a degree's n bit.
__device__ __forceinline__ MonomialPreimage monomial_preimage(
    uint32_t local, uint32_t n, uint32_t degree) {
    const uint32_t mask = n - 1;
    const uint32_t shift = degree & mask;
    return {(local + n - shift) & mask,
            ((degree & n) != 0) != (local < shift)};
}

template <class T>
__device__ __forceinline__ T block_add_canonical(T acc, T value, T q) {
    // Both operands are below q. Comparing against q-value avoids forming
    // an overflowing sum even when q is close to the coefficient word limit.
    const T threshold = q - value;
    return acc >= threshold ? acc - threshold : acc + value;
}

template <class T>
__device__ __forceinline__ T block_sub_canonical(T acc, T value, T q) {
    return acc >= value ? acc - value : q - (value - acc);
}

// Exact step-one RotationModulusSwitch for source modulus 2^input_bits
// (including the native word modulus) and target modulus 2^rotation_bits.
// The host establishes 1 <= input_bits <= T's width, 1 <= rotation_bits <= 32,
// and canonical source values. Every executed shift is below T's width.
template <class T>
__device__ __forceinline__ uint32_t quantize_block_exponent(
    T value, uint32_t input_bits, uint32_t rotation_bits, uint32_t rotation_mask) {
    T rounded;
    if (input_bits > rotation_bits) {
        const uint32_t shift = input_bits - rotation_bits;
        // Ties round up. Splitting quotient and rounding bit avoids adding a
        // half-step to a possibly maximal native word before the right shift.
        rounded = (value >> shift) + ((value >> (shift - 1)) & T{1});
    } else if (input_bits < rotation_bits) {
        // A larger binary target embeds every source point exactly.
        rounded = value << (rotation_bits - input_bits);
    } else {
        rounded = value;
    }
    return static_cast<uint32_t>(rounded) & rotation_mask;
}

// Input is [lane][mask coefficients..., body]. The host establishes
// count = lanes * (lwe_dimension + 1), a positive block_width dividing the
// positive logical dimension, and disjoint complete input/output buffers.
// Mask exponents are transposed to [block][lane][selector]; the final lanes
// entries hold already-negated body exponents, all modulo the target 2N.
template <class T>
__device__ __forceinline__ void quantize_block_inputs(
    const T* input, uint32_t* exponents, uint32_t count,
    uint32_t lwe_dimension, uint32_t block_width, uint32_t lanes,
    uint32_t input_bits, uint32_t rotation_bits) {
    const uint32_t rotation_mask = ~uint32_t{0} >> (32 - rotation_bits);
    const size_t input_stride = static_cast<size_t>(lwe_dimension) + 1;
    const size_t body_offset = static_cast<size_t>(lanes) * lwe_dimension;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t lane = index / input_stride;
        const size_t local = index % input_stride;
        const uint32_t exponent =
            quantize_block_exponent(input[index], input_bits, rotation_bits, rotation_mask);
        if (local == lwe_dimension) {
            // CPU BR initializes X^(-R(body)); do not quantize the phase or
            // negate the input before rounding, which would change ties.
            exponents[body_offset + lane] = (uint32_t{0} - exponent) & rotation_mask;
        } else {
            const size_t block = local / block_width;
            const size_t selector = local % block_width;
            exponents[(block * lanes + lane) * block_width + selector] = exponent;
        }
    }
}

// Each lane receives zero masks and the common canonical LUT multiplied by
// X^body_exponents[lane]. The exponent is already negated by quantization.
// Host binding establishes count = lanes * glwe_len, glwe_len >= n divisible
// by n, power-of-two n, and disjoint LUT, exponent and accumulator buffers.
template <class T>
__device__ __forceinline__ void initialize_block_accumulators(
    const T* lut, const uint32_t* body_exponents, T* accumulators,
    uint32_t count, uint32_t n, uint32_t glwe_len, T q) {
    const uint32_t body_offset = glwe_len - n;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t lane = index / glwe_len;
        const uint32_t local = static_cast<uint32_t>(index % glwe_len);
        if (local < body_offset) {
            accumulators[index] = T{0};
        } else {
            const auto preimage = monomial_preimage(local - body_offset, n,
                                                     body_exponents[lane]);
            const T value = lut[preimage.source];
            accumulators[index] = preimage.negate && value != 0 ? q - value : value;
        }
    }
}

// Host binding establishes power-of-two 2 <= n <= 2048, gadget_len divisible
// by n, positive block_width, has_dummy in {0,1}, and count=batch*gadget_len.
// block is [selector][gadget coefficient], followed by one complete dummy
// only when present. Exponents are [lane][selector], and aggregate is
// [lane][gadget coefficient]. Every key coefficient is canonical modulo q;
// aggregate is disjoint from both inputs and is completely overwritten.
template <class T>
__device__ __forceinline__ void aggregate_block(
    const T* block, const uint32_t* exponents, T* aggregate, uint32_t count,
    uint32_t n, uint32_t gadget_len, uint32_t block_width,
    uint32_t has_dummy, T q) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint32_t flat = static_cast<uint32_t>(index);
        const uint32_t lane = flat / gadget_len;
        const uint32_t coefficient = flat % gadget_len;
        const uint32_t local = coefficient & (n - 1);
        const uint32_t polynomial = coefficient - local;
        T acc = has_dummy
                    ? block[static_cast<size_t>(block_width) * gadget_len + coefficient]
                    : T{0};
        for (uint32_t selector = 0; selector < block_width; ++selector) {
            const uint32_t degree =
                exponents[static_cast<size_t>(lane) * block_width + selector];
            const auto preimage = monomial_preimage(local, n, degree);
            const T value = block[static_cast<size_t>(selector) * gadget_len +
                                  polynomial + preimage.source];
            acc = preimage.negate ? block_sub_canonical(acc, value, q)
                                  : block_add_canonical(acc, value, q);
        }
        aggregate[index] = acc;
    }
}

}  // namespace

extern "C" __global__ void primus_block_quantize_u32(
    const uint32_t* input, uint32_t* exponents, uint32_t count,
    uint32_t lwe_dimension, uint32_t block_width, uint32_t lanes,
    uint32_t input_bits, uint32_t rotation_bits) {
    quantize_block_inputs(input, exponents, count, lwe_dimension, block_width,
                           lanes, input_bits, rotation_bits);
}

extern "C" __global__ void primus_block_quantize_u64(
    const uint64_t* input, uint32_t* exponents, uint32_t count,
    uint32_t lwe_dimension, uint32_t block_width, uint32_t lanes,
    uint32_t input_bits, uint32_t rotation_bits) {
    quantize_block_inputs(input, exponents, count, lwe_dimension, block_width,
                           lanes, input_bits, rotation_bits);
}

extern "C" __global__ void primus_block_initialize_u32(
    const uint32_t* lut, const uint32_t* body_exponents, uint32_t* accumulators,
    uint32_t count, uint32_t n, uint32_t glwe_len, uint32_t q) {
    initialize_block_accumulators(lut, body_exponents, accumulators, count, n,
                                  glwe_len, q);
}

extern "C" __global__ void primus_block_initialize_u64(
    const uint64_t* lut, const uint32_t* body_exponents, uint64_t* accumulators,
    uint32_t count, uint32_t n, uint32_t glwe_len, uint64_t q) {
    initialize_block_accumulators(lut, body_exponents, accumulators, count, n,
                                  glwe_len, q);
}

extern "C" __global__ void primus_aggregate_block_u32(
    const uint32_t* block, const uint32_t* exponents, uint32_t* aggregate,
    uint32_t count, uint32_t n, uint32_t gadget_len, uint32_t block_width,
    uint32_t has_dummy, uint32_t q) {
    aggregate_block(block, exponents, aggregate, count, n, gadget_len,
                    block_width, has_dummy, q);
}

extern "C" __global__ void primus_aggregate_block_u64(
    const uint64_t* block, const uint32_t* exponents, uint64_t* aggregate,
    uint32_t count, uint32_t n, uint32_t gadget_len, uint32_t block_width,
    uint32_t has_dummy, uint64_t q) {
    aggregate_block(block, exponents, aggregate, count, n, gadget_len,
                    block_width, has_dummy, q);
}
