#pragma once

#include <stddef.h>
#include <stdint.h>

// The host establishes positive payload_digits, payload_rows and output_stride,
// index_len <= n, and output_stride = ceil((index_len + payload_digits*payload_rows)/n)*n.
// count is a complete batch of output_stride coefficients. Input records are
// [index coefficients][payload digits][row weights], all canonical in F257.
// Input/output are disjoint complete buffers and q >= 257.
extern "C" __global__ void primus_digest_pack_u64(
    const uint16_t* input, uint64_t* output, uint32_t count,
    uint32_t index_len, uint32_t payload_digits, uint32_t payload_rows,
    uint32_t output_stride, uint64_t q) {
    const size_t input_stride = static_cast<size_t>(index_len) + payload_digits + payload_rows;
    const size_t logical_length = static_cast<size_t>(payload_digits) * payload_rows + index_len;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint32_t local = static_cast<uint32_t>(index) % output_stride;
        const size_t record = static_cast<uint32_t>(index) / output_stride;
        const size_t start = record * input_stride;
        uint32_t value = 0;
        if (local < index_len) {
            value = input[start + local];
        } else if (local < logical_length) {
            const uint32_t position = local - index_len;
            const uint32_t row = position / payload_digits;
            const uint32_t digit = position % payload_digits;
            // The row's one sampled weight persists across physical-polynomial
            // boundaries. Two canonical F257 factors multiply to at most 65536.
            value = static_cast<uint32_t>(input[start + index_len + digit]) *
                    input[start + index_len + payload_digits + row] % 257;
        }
        // Lift the representative in [-128,128], without an encoding scale.
        // Padding takes value=0. q >= 257 makes every result canonical.
        output[index] = value <= 128 ? value : q - (257 - value);
    }
}
