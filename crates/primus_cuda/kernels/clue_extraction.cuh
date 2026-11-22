#pragma once

#include <stddef.h>
#include <stdint.h>

// Input:  [clue][shared mask of length dimension][four bodies].
// Output: [clue][sample 0..4][mask of length dimension][body].
// The host launches one 256-thread block per clue and establishes dimension >= 4,
// a binary modulus (modulus_mask = q-1, including native u32), canonical input,
// disjoint buffers, and checked complete allocations. dimension need not be a
// power of two. All four samples use the same recipient secret.
//
// A positive center_block_width and grid enable ExactlyOne body compensation.
// The host then establishes the CPU ClueBodyCenter conditions: complete equal
// blocks, q = (rotation_mask+1)*grid, power-of-two grid >= 2, and
// width*(q-1) + dimension*(grid/2) + width*grid/2 <= INT64_MAX.
// This bounds residual reductions, signed numerators and the positive divisor.
// If either width or grid is zero, bodies are copied without compensation.
extern "C" __global__ void primus_extract_clues_u32(
    const uint32_t* clues, uint32_t* output, uint32_t dimension,
    uint32_t modulus_mask, uint32_t center_block_width,
    uint32_t grid, uint32_t rotation_mask) {
    __shared__ int64_t residual_sums[256];
    const size_t clue_offset =
        static_cast<size_t>(blockIdx.x) * (static_cast<size_t>(dimension) + 4);
    const size_t lwe_len = static_cast<size_t>(dimension) + 1;
    const size_t output_offset = static_cast<size_t>(blockIdx.x) * 4 * lwe_len;
    const bool center = center_block_width != 0 && grid != 0;
    const uint32_t grid_mask = grid - 1;
    const int64_t half_grid = static_cast<int64_t>(grid) / 2;
    int64_t partial_sum = 0;

    for (size_t coefficient = threadIdx.x; coefficient < dimension;
         coefficient += blockDim.x) {
        const uint32_t raw = clues[clue_offset + coefficient];
        output[output_offset + coefficient] = raw;
        if (center) {
            // Unwrapped nearest-grid residual. An exact half-grid tie is
            // negative because the ordinary quantizer rounds upward.
            const int64_t low = raw & grid_mask;
            partial_sum += low - (low >= half_grid ? static_cast<int64_t>(grid) : 0);
        }

        #pragma unroll
        for (uint32_t sample = 1; sample < 4; ++sample) {
            const size_t source = coefficient >= sample
                ? coefficient - sample : coefficient + dimension - sample;
            const uint32_t value = clues[clue_offset + source];
            // Signed right rotation: only the wrapped prefix changes sign.
            // Unsigned negation plus the binary mask also preserves zero.
            output[output_offset + sample * lwe_len + coefficient] =
                coefficient < sample ? (uint32_t{0} - value) & modulus_mask : value;
        }
    }

    if (center) {
        residual_sums[threadIdx.x] = partial_sum;
        __syncthreads();
        for (uint32_t offset = 128; offset != 0; offset /= 2) {
            if (threadIdx.x < offset) {
                residual_sums[threadIdx.x] += residual_sums[threadIdx.x + offset];
            }
            // The center predicate is uniform across the block, and threads
            // without mask coefficients still contribute zero and participate.
            __syncthreads();
        }

        if (threadIdx.x < 4) {
            const uint32_t sample = threadIdx.x;
            int64_t residual_sum = residual_sums[0];
            for (uint32_t rotation = 0; rotation < sample; ++rotation) {
                const uint32_t value = clues[clue_offset + dimension - 1 - rotation];
                const int64_t low = value & grid_mask;
                const int64_t residual =
                    low - (low >= half_grid ? static_cast<int64_t>(grid) : 0);
                // res(-a) = -res(a), except at low=grid/2 where both
                // residuals equal -grid/2. Preserve that extra tie correction.
                residual_sum -= 2 * residual
                    + (low == half_grid ? static_cast<int64_t>(grid) : 0);
            }

            const uint32_t body = clues[clue_offset + dimension + sample];
            const int64_t divisor = static_cast<int64_t>(center_block_width) * grid;
            const int64_t numerator =
                static_cast<int64_t>(center_block_width) * body - residual_sum + divisor / 2;
            // C++ signed division truncates toward zero. A negative remainder
            // needs one more decrement to reproduce CPU div_euclid(divisor).
            int64_t quotient = numerator / divisor;
            if (numerator % divisor < 0) {
                --quotient;
            }
            const uint64_t exponent = static_cast<uint64_t>(quotient) & rotation_mask;
            // The body lies on the old grid, so BR quantizes it exactly once.
            output[output_offset + sample * lwe_len + dimension] =
                static_cast<uint32_t>(exponent * grid);
        }
    } else if (threadIdx.x < 4) {
        const uint32_t sample = threadIdx.x;
        output[output_offset + sample * lwe_len + dimension] =
            clues[clue_offset + dimension + sample];
    }
}
