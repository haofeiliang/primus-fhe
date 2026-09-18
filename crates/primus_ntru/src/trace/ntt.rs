//! Coefficient-domain NTRU trace with exact modular normalization.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntt::NttTable;
use primus_reduce::{FieldContext, ReduceNeg};

use super::kernels;
use crate::{
    NlevParameters, NtruCiphertext, NtruSecretKey, NttNtruAutomorphismContext,
    NttNtruAutomorphismKey, NttNtruGadgetEncryptContext, NttNtruSecretKey,
};

/// Reusable coefficient buffers for NTT-key trace, projection and expansion.
pub struct NttNtruTraceContext<T: FheUint> {
    automorphism_output: NtruCiphertext<Vec<T>>,
    automorphism: NttNtruAutomorphismContext<T>,
}

impl<T: FheUint> NttNtruTraceContext<T> {
    /// Allocates workspace for one polynomial length.
    ///
    /// # Panics
    /// Inherits [`NttNtruAutomorphismContext::new`]'s supported-length check.
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        let automorphism = NttNtruAutomorphismContext::new(poly_length);
        Self {
            automorphism_output: NtruCiphertext::zero(poly_length),
            automorphism,
        }
    }
}

/// The `log2(N)` automorphism keys used by trace, projection and expansion.
/// Inputs and outputs stay in coefficient form under the original NTRU secret.
#[derive(Clone)]
pub struct NttNtruTraceKey<T: FheUint> {
    automorphism_keys: Vec<NttNtruAutomorphismKey<T>>,
    inverse_two: T,
    // Entry j normalizes expansion of 2^j coefficients before the tree.
    inverse_expansion_lengths: Vec<ShoupFactor<T>>,
}

impl<T: FheUint> NttNtruTraceKey<T> {
    /// Generates keys for degrees `N+1, N/2+1, ..., 3` under one secret.
    ///
    /// # Correctness
    /// Inherits [`NttNtruAutomorphismKey::generate`]'s key identity, bounded
    /// signed coefficients and NTT representation requirements.
    ///
    /// # Panics
    /// Inherits that method's resource checks. Also panics before sampling
    /// unless the ciphertext modulus is odd and below `2^(T::BITS-1)`, as
    /// required by the precomputed normalization factors.
    #[must_use]
    pub fn generate<M, Table, R>(
        secret_key: &NtruSecretKey<T>,
        ntt_secret_key: &NttNtruSecretKey<T>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let q = parameters.ntru().cipher_modulus().value();
        assert!(
            q & T::ONE == T::ONE && q < T::ONE << (T::BITS - 1),
            "trace normalization requires an odd modulus below 2^(T::BITS-1)"
        );
        let log_n = parameters.poly_length().trailing_zeros();
        let automorphism_keys = (1..=log_n)
            .rev()
            .map(|shift| {
                NttNtruAutomorphismKey::generate(
                    (1usize << shift) + 1,
                    secret_key,
                    ntt_secret_key,
                    parameters,
                    ntt,
                    rng,
                    context,
                )
            })
            .collect();
        let inverse_two = (q >> 1u32) + T::ONE;
        let mut inverse = T::ONE;
        let mut inverse_expansion_lengths = Vec::with_capacity(log_n as usize + 1);
        for _ in 0..=log_n {
            inverse_expansion_lengths.push(ShoupFactor::new(inverse, q));
            inverse = (inverse >> 1u32) + (inverse & T::ONE) * inverse_two;
        }
        Self {
            automorphism_keys,
            inverse_two,
            inverse_expansion_lengths,
        }
    }

    /// Returns the unchanged ring polynomial length N.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.automorphism_keys[0].poly_length()
    }

    /// Returns the number of available automorphism keys, log2(N).
    #[must_use]
    pub fn automorphism_count(&self) -> usize {
        self.automorphism_keys.len()
    }

    /// Returns the decomposition basis shared by all automorphism keys.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.automorphism_keys[0].basis()
    }

    /// Applies full ordinary trace, targeting the constant message `N*M[0]`.
    ///
    /// # Correctness
    /// Input contains canonical residues under the original secret and key
    /// modulus. Use the generation NTT representation. Noise, including
    /// key-switch errors and trace amplification, must fit the caller's budget.
    ///
    /// # Panics
    /// Panics before writes if input/output, workspace or NTT lengths, or
    /// arithmetic/table moduli do not match the key.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_partial_to(input, 1, output, modulus, ntt, context);
    }

    /// Retains `r=retained_coefficient_count` equally spaced message positions.
    /// With `d=N/r`, targets `d * sum_j M[j*d] X^(j*d)` in the original ring.
    /// `r=N` copies the input; `r=1` is full trace.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key, representation and noise requirements.
    ///
    /// # Panics
    /// Inherits that method's resource checks. Also panics before writes unless
    /// `retained_coefficient_count` is a power-of-two divisor of N.
    pub fn apply_partial_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_io(input.as_ref(), output.as_ref(), modulus, ntt, context);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, _, false>(output.as_mut(), levels, modulus, ntt, context);
    }

    /// Applies full normalized reverse trace, targeting the constant message `M[0]`.
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and panic contracts.
    pub fn apply_reverse_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_reverse_partial_to(input, 1, output, modulus, ntt, context);
    }

    /// Applies normalized reverse trace to `r=retained_coefficient_count` positions.
    /// With `d=N/r`, targets `sum_j M[j*d] X^(j*d)` without changing ring degree.
    /// Keys are visited in ascending degree; `r=N` copies input.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key and representation requirements.
    /// Halving multiplies canonical residues by `2^-1 mod q`; it is not rounded
    /// integer division and does not inherit native-torus noise bounds. Errors
    /// from input and automorphism keys undergo the remaining modular maps;
    /// residual key-switch error can occupy non-target coefficients. The caller
    /// must bound this error for the chosen secret, basis and message scale.
    ///
    /// # Panics
    /// Inherits [`Self::apply_partial_to`]'s prewrite checks.
    pub fn apply_reverse_partial_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_io(input.as_ref(), output.as_ref(), modulus, ntt, context);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, _, true>(output.as_mut(), levels, modulus, ntt, context);
    }

    /// Projects one coefficient to the constant position using a monomial shift
    /// followed by reverse trace. Inherits [`Self::project_coefficients_to`]'s
    /// numerical and prewrite checks; `index` must be below N.
    pub fn project_coefficient_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        index: usize,
        output: &mut NtruCiphertext<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.project_coefficients_to(input, &[index], output.as_mut(), modulus, ntt, context);
    }

    /// Projects selected coefficients into consecutive NTRU blocks in `indices`
    /// order, including duplicates. Performs one reverse trace per index.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and representation
    /// requirements. Each block targets a constant; noise can remain in its tail.
    ///
    /// # Panics
    /// Panics before writes if any index is outside `[0,N)`, output does not
    /// contain exactly `indices.len()*N` coefficients, or input/resources do not
    /// match the key. Empty indices require empty output, but still validate resources.
    pub fn project_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        indices: &[usize],
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert!(
            indices.iter().all(|&index| index < self.poly_length()),
            "projection index outside polynomial"
        );
        self.project_indices_to(
            input,
            indices.iter().copied(),
            output,
            modulus,
            ntt,
            context,
        );
    }

    /// Projects coefficients `0..count` into consecutive constant-message NTRUs.
    /// Accepts any `count` in `0..=N`; no zero message tail is required.
    /// Uses one full reverse trace per coefficient, with the same rounding and
    /// error behavior as [`Self::project_coefficients_to`], and allocates nothing.
    /// Inherits that method's numerical and representation requirements.
    ///
    /// # Panics
    /// Panics before writes if `count > N`, output does not contain exactly
    /// `count * N` coefficients, or input/backend/workspace layouts differ
    /// from the key. Zero count requires empty output and still validates resources.
    pub fn project_prefix_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert!(
            count <= self.poly_length(),
            "projection prefix exceeds polynomial length"
        );
        self.project_indices_to(input, 0..count, output, modulus, ntt, context);
    }

    // Public callers validate the index range. Check the remaining layouts
    // once, then use the same arithmetic for a slice iterator or a prefix range.
    fn project_indices_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        indices: impl ExactSizeIterator<Item = usize>,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.check_batch(input.as_ref(), indices.len(), output, modulus, ntt, context);
        let n = self.poly_length();
        let exponents = PowOf2Modulus::new(2 * n);
        for (index, output) in indices.zip(output.chunks_exact_mut(n)) {
            input.mul_monomial_to(
                exponents.reduce_neg(index),
                &mut NtruCiphertext::new(&mut *output),
                modulus,
            );
            self.trace_kernel_assign::<_, _, true>(
                output,
                self.automorphism_count(),
                modulus,
                ntt,
                context,
            );
        }
    }

    /// Expands every coefficient to a constant-message NTRU in natural order.
    /// Equivalent to [`Self::expand_partial_coefficients_to`] with count=N,
    /// requiring no message zero-tail assumption. Output holds N*N coefficients.
    pub fn expand_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.expand_partial_coefficients_to(
            input,
            self.poly_length(),
            output,
            modulus,
            ntt,
            context,
        );
    }

    /// Expands a message supported on its first `count` coefficients to `count`
    /// constant-message NTRUs in natural order, in the same N-coefficient ring.
    /// Uses output as tree storage and count-1 automorphisms without allocation.
    ///
    /// # Correctness
    /// The target message must be zero at every position >= count. Neither the
    /// ciphertext nor its noise needs a zero tail. A general message instead
    /// yields residue-class polynomials `sum_j M[i+j*count] X^(j*count)`.
    /// Inherits [`Self::apply_to`]'s representation requirements. Normalization
    /// multiplies input by `count^-1 mod q` before the unscaled tree. Its modular
    /// error distribution differs from reverse-trace projection and must fit
    /// the caller's budget; non-target output coefficients can contain noise.
    ///
    /// # Panics
    /// Panics before writes unless count is a power-of-two divisor of N,
    /// output has exactly count*N coefficients, and input/resources match the key.
    pub fn expand_partial_coefficients_to<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        kernels::check_count(self.poly_length(), count);
        self.check_batch(input.as_ref(), count, output, modulus, ntt, context);
        if count == 1 {
            output.copy_from_slice(input.as_ref());
            return;
        }
        let factor = self.inverse_expansion_lengths[count.trailing_zeros() as usize];
        let NttNtruTraceContext {
            automorphism_output,
            automorphism,
        } = context;
        kernels::expand_to(
            input.as_ref(),
            output,
            automorphism_output.as_mut(),
            modulus,
            |values| factor.factor_mul_slice_assign(values, modulus.value()),
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    &NtruCiphertext::new(input),
                    &mut NtruCiphertext::new(output),
                    modulus,
                    ntt,
                    automorphism,
                )
            },
        );
    }

    fn check_io<M: FieldContext<T>, Table: NttTable<ValueT = T>>(
        &self,
        input: &[T],
        output: &[T],
        modulus: M,
        ntt: &Table,
        context: &NttNtruTraceContext<T>,
    ) {
        self.check_batch(input, 1, output, modulus, ntt, context);
    }

    fn check_batch<M: FieldContext<T>, Table: NttTable<ValueT = T>>(
        &self,
        input: &[T],
        count: usize,
        output: &[T],
        modulus: M,
        ntt: &Table,
        context: &NttNtruTraceContext<T>,
    ) {
        assert_eq!(
            input.len(),
            self.poly_length(),
            "trace input length mismatch"
        );
        assert_eq!(
            output.len(),
            count
                .checked_mul(self.poly_length())
                .expect("trace output length overflow"),
            "trace output length mismatch"
        );
        self.automorphism_keys[0].assert_compatible(modulus, ntt, &context.automorphism);
    }

    /// Requires checked operands/resources; all keys share one immutable domain.
    fn trace_kernel_assign<M: FieldContext<T>, Table: NttTable<ValueT = T>, const REVERSE: bool>(
        &self,
        output: &mut [T],
        levels: usize,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTraceContext<T>,
    ) {
        let NttNtruTraceContext {
            automorphism_output,
            automorphism,
        } = context;
        kernels::trace_assign::<_, _, _, _, REVERSE>(
            output,
            levels,
            automorphism_output.as_mut(),
            modulus,
            |values| {
                // Canonical inv2 multiplication, without division or a full
                // modular product. Both terms sum to a residue below q.
                for value in values {
                    *value = (*value >> 1u32) + (*value & T::ONE) * self.inverse_two;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    &NtruCiphertext::new(input),
                    &mut NtruCiphertext::new(output),
                    modulus,
                    ntt,
                    automorphism,
                )
            },
        );
    }
}
