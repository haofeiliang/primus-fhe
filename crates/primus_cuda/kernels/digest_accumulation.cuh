#pragma once

#include <stddef.h>
#include <stdint.h>

// Included after ntt.cu's exact multiply_mod_u64 and reduce_once helpers.
// The host establishes a positive power-of-two n, positive components and
// physical_polynomials, count = physical_polynomials*components*n, and complete
// disjoint buffers on one ordered stream. All coefficients are canonical for
// the same NTT roots/order/normalization, with 2 <= q, q_bits <= 62, and
// reciprocal = floor(2^(2*q_bits)/q). q_bits is the bit length of q.
//
// Layouts: sums[physical polynomial][component][coefficient],
// flags_ntt[clue][component][coefficient], and
// public_ntt[clue][physical polynomial][coefficient]. Every component of one
// flag multiplies the same public polynomial. Each physical ciphertext keeps
// its own mask: distinct public polynomials do not preserve a shared mask.
extern "C" __global__ void primus_digest_accumulate_u64(
    uint64_t* sums, const uint64_t* flags_ntt, const uint64_t* public_ntt,
    uint32_t count, uint32_t n, uint32_t components,
    uint32_t physical_polynomials, uint32_t clues, uint64_t q,
    uint32_t q_bits, uint64_t reciprocal) {
    const uint32_t log_n = 31 - __clz(n);
    const size_t flag_stride = static_cast<size_t>(components) * n;
    const size_t public_stride = static_cast<size_t>(physical_polynomials) * n;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint32_t local = static_cast<uint32_t>(index) & (n - 1);
        const uint32_t polynomial = static_cast<uint32_t>(index) >> log_n;
        const uint32_t component = polynomial % components;
        const uint32_t physical = polynomial / components;
        const size_t flag_offset = static_cast<size_t>(component) * n + local;
        const size_t public_offset = static_cast<size_t>(physical) * n + local;
        uint64_t acc = sums[index];
        // A thread owns one complete clue reduction, so no atomics or temporary
        // products are needed. Keep the original clue order and all flag noise,
        // including nonconstant coefficients and final logical padding.
        for (uint32_t clue = 0; clue < clues; ++clue) {
            const uint64_t product = multiply_mod_u64(
                flags_ntt[static_cast<size_t>(clue) * flag_stride + flag_offset],
                public_ntt[static_cast<size_t>(clue) * public_stride + public_offset],
                q, q_bits, reciprocal);
            // acc, product < q < 2^62, so the unsigned sum cannot overflow and
            // is below 2q. One subtraction preserves canonical residues.
            acc = reduce_once(acc + product, q);
        }
        sums[index] = acc;
    }
}
