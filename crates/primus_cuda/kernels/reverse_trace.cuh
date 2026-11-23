#pragma once

#include <stddef.h>
#include <stdint.h>

// The host binds an odd q < 2^62, a power-of-two n <= 2048, an odd
// automorphism degree in [1, 2n), and disjoint complete polynomial batches.
// Reverse trace halves BEFORE the automorphism and its approximate key switch;
// moving this factor after key switching would change the ciphertext result.
extern "C" __global__ void primus_reverse_trace_prepare_u64(
    const uint64_t* input, uint64_t* halved, uint64_t* permuted,
    uint32_t count, uint32_t n, uint32_t degree, uint64_t q) {
    const uint64_t inverse_two = (q >> 1) + 1;
    const uint32_t mask = n - 1;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint64_t value = input[index];
        // For canonical value, an even value maps to value/2 and an odd value
        // to (value+q)/2, without forming value+q. Both are canonical, and this
        // agrees exactly with the CPU field-inverse-two normalization.
        const uint64_t half = (value >> 1) + (value & 1) * inverse_two;
        halved[index] = half;

        const uint32_t local = static_cast<uint32_t>(index) & mask;
        // local*degree < 2048*4096 fits u32. Odd degree permutes positions
        // modulo n bijectively, so these scattered writes never race. Bit n
        // records the sign from X^n = -1; higher bits are multiples of 2n.
        const uint32_t exponent = local * degree;
        const size_t destination = index - local + (exponent & mask);
        permuted[destination] = (exponent & n) != 0 && half != 0 ? q - half : half;
    }
}

extern "C" __global__ void primus_reverse_trace_add_u64(
    uint64_t* state, const uint64_t* halved, uint32_t count, uint64_t q) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        // Both operands are canonical and q < 2^62, hence sum < 2^63.
        // One subtraction restores the canonical coefficient representation.
        const uint64_t sum = state[index] + halved[index];
        state[index] = sum >= q ? sum - q : sum;
    }
}
