#include <stddef.h>
#include <stdint.h>

#include "block_rotation.cuh"

// Host wrappers establish all geometry, allocation, and numerical contracts
// before launching. Transforms use one block per contiguous polynomial, a
// one-dimensional block, and n * sizeof(T) bytes of dynamic shared memory.
// Here 2 <= n <= 2048 is a power of two, coefficients are canonical, and the
// roots belong to the exact CPU table's negacyclic, bit-reversed convention.
// NTT moduli satisfy q < 2^30 (u32) or q < 2^62 (u64), so 4q fits the word.

namespace {

__device__ __forceinline__ uint32_t high_product(uint32_t lhs, uint32_t rhs) {
    return __umulhi(lhs, rhs);
}

__device__ __forceinline__ uint64_t high_product(uint64_t lhs, uint64_t rhs) {
    return __umul64hi(static_cast<unsigned long long>(lhs),
                      static_cast<unsigned long long>(rhs));
}

template <class T>
__device__ __forceinline__ T reduce_once(T value, T modulus) {
    return value >= modulus ? value - modulus : value;
}

// For R = 2^word_bits, precon = floor(root * R / q), 0 <= root < q,
// and 0 <= value < 4q < R. The high product estimates floor(value*root/q)
// from below with error at most one, so the true remainder is in [0, 2q).
// Both low products and their unsigned subtraction are intentionally modulo R;
// the true remainder fits a word, making that low word the exact remainder.
template <class T>
__device__ __forceinline__ T shoup_lazy(T value, T root, T precon, T q) {
    const T quotient = high_product(value, precon);
    return value * root - quotient * q;
}

__device__ __forceinline__ uint32_t multiply_mod_u32(
    uint32_t lhs, uint32_t rhs, uint32_t q) {
    // Canonical u32 factors have an exact product in u64. This initial
    // reference path leaves division replacement to measured optimization.
    return static_cast<uint64_t>(lhs) * rhs % q;
}

// Canonical multiplication for 2 <= q, b = bit_length(q) <= 62, and
// reciprocal = floor(2^(2b) / q). For x = lhs*rhs < q^2 < 2^(2b),
// floor(x*reciprocal / 2^(2b)) is floor(x/q) or one less: replacing
// 2^(2b)/q by its floor introduces an error strictly below one.
// Compute the needed limbs of the 128-by-64 product without truncating x.
__device__ __forceinline__ uint64_t multiply_mod_u64(
    uint64_t lhs, uint64_t rhs, uint64_t q, uint32_t q_bits,
    uint64_t reciprocal) {
    const uint64_t product_low = lhs * rhs;
    uint64_t quotient;
    if (q_bits < 32) {
        // x fits 64 bits. Since 2 <= b < 32, both shifts are in [1, 63].
        const uint32_t shift = 2 * q_bits;
        const uint64_t scaled_low = product_low * reciprocal;
        const uint64_t scaled_high = high_product(product_low, reciprocal);
        quotient = (scaled_low >> shift) | (scaled_high << (64 - shift));
    } else {
        const uint64_t product_high = high_product(lhs, rhs);
        const uint64_t lower_high = high_product(product_low, reciprocal);
        const uint64_t upper_low = product_high * reciprocal;
        const uint64_t middle = lower_high + upper_low;
        const uint32_t shift = 2 * q_bits - 64;
        if (shift == 0) {
            quotient = middle;
        } else {
            const uint64_t carry = middle < lower_high;
            const uint64_t upper = high_product(product_high, reciprocal) + carry;
            quotient = (middle >> shift) | (upper << (64 - shift));
        }
    }

    // The exact nonnegative remainder is below 2q < 2^63. Modular low-word
    // subtraction therefore recovers it even when the products exceed 64 bits.
    const uint64_t remainder = product_low - quotient * q;
    return reduce_once(remainder, q);
}

// Each output coefficient reads its unique preimage under multiplication by
// X^degree in Z_q[X]/(X^n+1). The host establishes complete length-n batches,
// power-of-two n, 0 <= degree < 2n, canonical input, and disjoint buffers.
template <class T>
__device__ __forceinline__ void multiply_monomial(
    const T* input, T* output, uint32_t count, uint32_t n, uint32_t degree, T q) {
    const uint32_t mask = n - 1;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint32_t local = static_cast<uint32_t>(index & mask);
        const auto preimage = monomial_preimage(local, n, degree);
        const T value = input[index - local + preimage.source];
        // Negating zero must produce canonical zero rather than q.
        output[index] = preimage.negate && value != 0 ? q - value : value;
    }
}

template <class T>
__device__ __forceinline__ void forward(
    T* values, const T* roots, const T* roots_precon, uint32_t n, T q,
    T* shared) {
    const size_t offset = static_cast<size_t>(blockIdx.x) * n;
    for (uint32_t index = threadIdx.x; index < n; index += blockDim.x) {
        shared[index] = values[offset + index];
    }
    __syncthreads();

    const T twice_q = q + q;
    const uint32_t log_n = 31 - __clz(n);
    for (uint32_t stage = 0; stage < log_n; ++stage) {
        const uint32_t gap_log = log_n - stage - 1;
        const uint32_t gap = uint32_t{1} << gap_log;
        const uint32_t groups = uint32_t{1} << stage;
        for (uint32_t butterfly = threadIdx.x; butterfly < n / 2;
             butterfly += blockDim.x) {
            const uint32_t group = butterfly >> gap_log;
            // gap is a power of two. Map a linear butterfly to its pair
            // without integer division: first = 2 * group * gap + within.
            const uint32_t first = (butterfly << 1) - (butterfly & (gap - 1));
            const uint32_t root_index = groups + group;
            const T x = reduce_once(shared[first], twice_q);
            const T y = shoup_lazy(shared[first + gap], roots[root_index],
                                   roots_precon[root_index], q);
            // x,y < 2q, so both outputs are in [0,4q) and no sum overflows.
            shared[first] = x + y;
            shared[first + gap] = x + twice_q - y;
        }
        // Every thread participates, including threads without a butterfly.
        // Distinct butterflies own disjoint pairs within each stage.
        __syncthreads();
    }

    for (uint32_t index = threadIdx.x; index < n; index += blockDim.x) {
        values[offset + index] = reduce_once(reduce_once(shared[index], twice_q), q);
    }
}

template <class T>
__device__ __forceinline__ void inverse(
    T* values, const T* roots, const T* roots_precon, uint32_t n, T q,
    T inv_n, T inv_n_precon, T* shared) {
    const size_t offset = static_cast<size_t>(blockIdx.x) * n;
    for (uint32_t index = threadIdx.x; index < n; index += blockDim.x) {
        shared[index] = values[offset + index];
    }
    __syncthreads();

    const T twice_q = q + q;
    const uint32_t log_n = 31 - __clz(n);
    uint32_t root_base = 1;
    for (uint32_t stage = 0; stage < log_n; ++stage) {
        const uint32_t gap = uint32_t{1} << stage;
        const uint32_t groups = n >> (stage + 1);
        for (uint32_t butterfly = threadIdx.x; butterfly < n / 2;
             butterfly += blockDim.x) {
            const uint32_t group = butterfly >> stage;
            const uint32_t first = (butterfly << 1) - (butterfly & (gap - 1));
            const uint32_t root_index = root_base + group;
            const T x = shared[first];
            const T y = shared[first + gap];
            // x,y < 2q. Both intermediate sums fit below 4q, and the
            // subtraction is nonnegative; each stage restores [0,2q).
            shared[first] = reduce_once(x + y, twice_q);
            shared[first + gap] = shoup_lazy(x + twice_q - y, roots[root_index],
                                            roots_precon[root_index], q);
        }
        __syncthreads();
        root_base += groups;
    }

    // Normalize inside the same launch. inv_n_precon uses the full word width,
    // independently of the CPU table's selected SIMD/preconditioner width.
    for (uint32_t index = threadIdx.x; index < n; index += blockDim.x) {
        values[offset + index] =
            reduce_once(shoup_lazy(shared[index], inv_n, inv_n_precon, q), q);
    }
}

}  // namespace

extern "C" __global__ void primus_smoke(
    const uint32_t* input, uint32_t* output, uint32_t count) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        output[index] = input[index] + uint32_t{1};
    }
}

extern "C" __global__ void primus_mul_u32(
    uint32_t* lhs, const uint32_t* rhs, uint32_t count, uint32_t q) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        lhs[index] = multiply_mod_u32(lhs[index], rhs[index], q);
    }
}

extern "C" __global__ void primus_mul_u64(
    uint64_t* lhs, const uint64_t* rhs, uint32_t count, uint64_t q,
    uint32_t q_bits, uint64_t reciprocal) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        lhs[index] = multiply_mod_u64(lhs[index], rhs[index], q, q_bits, reciprocal);
    }
}

extern "C" __global__ void primus_mul_add_u32(
    uint32_t* acc, const uint32_t* lhs, const uint32_t* rhs,
    uint32_t count, uint32_t q) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint32_t product = multiply_mod_u32(lhs[index], rhs[index], q);
        // The sum is below 2q. Widen it so this correction also supports
        // canonical u32 inputs when 2q does not fit the coefficient word.
        const uint64_t sum = static_cast<uint64_t>(acc[index]) + product;
        acc[index] = reduce_once(sum, static_cast<uint64_t>(q));
    }
}

extern "C" __global__ void primus_mul_add_u64(
    uint64_t* acc, const uint64_t* lhs, const uint64_t* rhs,
    uint32_t count, uint64_t q, uint32_t q_bits, uint64_t reciprocal) {
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
         index < count; index += stride) {
        const uint64_t product =
            multiply_mod_u64(lhs[index], rhs[index], q, q_bits, reciprocal);
        // Both terms are canonical, so the sum is below 2q < 2^63.
        acc[index] = reduce_once(acc[index] + product, q);
    }
}

extern "C" __global__ void primus_mul_monomial_u32(
    const uint32_t* input, uint32_t* output, uint32_t count,
    uint32_t n, uint32_t degree, uint32_t q) {
    multiply_monomial(input, output, count, n, degree, q);
}

extern "C" __global__ void primus_mul_monomial_u64(
    const uint64_t* input, uint64_t* output, uint32_t count,
    uint32_t n, uint32_t degree, uint64_t q) {
    multiply_monomial(input, output, count, n, degree, q);
}

extern "C" __global__ void primus_forward_u32(
    uint32_t* values, const uint32_t* roots, const uint32_t* roots_precon,
    uint32_t n, uint32_t q) {
    extern __shared__ __align__(8) unsigned char shared_memory[];
    forward(values, roots, roots_precon, n, q,
            reinterpret_cast<uint32_t*>(shared_memory));
}

extern "C" __global__ void primus_forward_u64(
    uint64_t* values, const uint64_t* roots, const uint64_t* roots_precon,
    uint32_t n, uint64_t q) {
    extern __shared__ __align__(8) unsigned char shared_memory[];
    forward(values, roots, roots_precon, n, q,
            reinterpret_cast<uint64_t*>(shared_memory));
}

extern "C" __global__ void primus_inverse_u32(
    uint32_t* values, const uint32_t* roots, const uint32_t* roots_precon,
    uint32_t n, uint32_t q, uint32_t inv_n, uint32_t inv_n_precon) {
    extern __shared__ __align__(8) unsigned char shared_memory[];
    inverse(values, roots, roots_precon, n, q, inv_n, inv_n_precon,
            reinterpret_cast<uint32_t*>(shared_memory));
}

extern "C" __global__ void primus_inverse_u64(
    uint64_t* values, const uint64_t* roots, const uint64_t* roots_precon,
    uint32_t n, uint64_t q, uint64_t inv_n, uint64_t inv_n_precon) {
    extern __shared__ __align__(8) unsigned char shared_memory[];
    inverse(values, roots, roots_precon, n, q, inv_n, inv_n_precon,
            reinterpret_cast<uint64_t*>(shared_memory));
}

#include "external_product.cuh"
