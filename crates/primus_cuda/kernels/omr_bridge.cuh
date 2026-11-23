#pragma once

// The host validates complete batches and disjoint views. GLWEs are rank one,
// in mask-then-body order. `count` always denotes the number of output words.
extern "C" __global__ void primus_omr_sum_four_u32(
    const uint32_t* input, uint32_t* output, uint32_t count, uint32_t glwe_len, uint32_t q) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t offset = (index / glwe_len) * (4 * glwe_len) + index % glwe_len;
        const uint32_t sum = input[offset] + input[offset + glwe_len]
            + input[offset + 2 * glwe_len] + input[offset + 3 * glwe_len];
        // The NTT modulus leaves two free bits, so a sum of four residues fits.
        output[index] = reduce_once(reduce_once(sum, q + q), q);
    }
}

extern "C" __global__ void primus_omr_extract_u32(
    const uint32_t* input, uint32_t* output, uint32_t count, uint32_t n,
    uint32_t lwe_len, uint32_t q) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const size_t glwe_offset = (index / lwe_len) * (2 * n);
        const uint32_t local = static_cast<uint32_t>(index % lwe_len);
        if (local == lwe_len - 1) {
            output[index] = input[glwe_offset + n];
        } else if (local == 0) {
            output[index] = input[glwe_offset];
        } else {
            const uint32_t value = input[glwe_offset + n - local];
            output[index] = value == 0 ? 0 : q - value;
        }
    }
}

extern "C" __global__ void primus_omr_switch_u32_to_u64(
    const uint32_t* input, uint64_t* output, uint32_t count, uint32_t q,
    uint64_t reciprocal) {
    constexpr uint32_t target = 4096;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint64_t numerator = static_cast<uint64_t>(input[index]) * target + q / 2;
        // reciprocal = floor(2^64/q). The estimate is at most one short
        // for every numerator below 2^64; correct using its exact remainder.
        const uint64_t quotient = high_product(numerator, reciprocal);
        const uint64_t rounded = quotient + (numerator - quotient * q >= q);
        output[index] = rounded & (target - 1);
    }
}
