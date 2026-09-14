//! Coefficient-domain native-torus trace with integer representative halving.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_reduce::ReduceNeg;

use super::kernels;
use crate::{
    FourierNtruAutomorphismContext, FourierNtruAutomorphismKey, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey, NlevParameters, NtruCiphertext, NtruSecretKey,
};

/// Reusable coefficient buffers for Fourier-key trace, projection and expansion.
pub struct FourierNtruTraceContext<T: TorusFftValue> {
    automorphism_output: NtruCiphertext<Vec<T>>,
    automorphism: FourierNtruAutomorphismContext<T>,
}

impl<T: TorusFftValue> FourierNtruTraceContext<T> {
    /// Allocates workspace for one polynomial length.
    ///
    /// # Panics
    /// Inherits [`FourierNtruAutomorphismContext::new`]'s supported-length check.
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        let automorphism = FourierNtruAutomorphismContext::new(poly_length);
        Self {
            automorphism_output: NtruCiphertext::zero(poly_length),
            automorphism,
        }
    }
}

/// The `log2(N)` automorphism keys used by native-torus trace and expansion.
/// Inputs and outputs stay in coefficient form under the original secret;
/// evaluation keys remain bound to the generating FFT table instance.
#[derive(Clone)]
pub struct FourierNtruTraceKey<T: TorusFftValue> {
    automorphism_keys: Vec<FourierNtruAutomorphismKey<T>>,
}

impl<T: TorusFftValue> FourierNtruTraceKey<T> {
    /// Generates keys for degrees `N+1, N/2+1, ..., 3` under one secret.
    ///
    /// # Correctness
    /// Inherits [`FourierNtruAutomorphismKey::generate`]'s key identity and
    /// FFT table instance and precision requirements.
    ///
    /// # Panics
    /// Inherits that method's key, parameter, table and workspace checks.
    #[must_use]
    pub fn generate<Table, R>(
        secret_key: &NtruSecretKey<T>,
        fourier_secret_key: &FourierNtruSecretKey,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let automorphism_keys = (1..=parameters.poly_length().trailing_zeros())
            .rev()
            .map(|shift| {
                FourierNtruAutomorphismKey::generate(
                    (1usize << shift) + 1,
                    secret_key,
                    fourier_secret_key,
                    parameters,
                    fft,
                    rng,
                    context,
                )
            })
            .collect();
        Self { automorphism_keys }
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

    /// Returns the native-torus basis shared by all automorphism keys.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.automorphism_keys[0].basis()
    }

    /// Applies full ordinary trace, targeting the constant message `N*M[0]`.
    ///
    /// # Correctness
    /// Input uses the original secret and key's native integer width. Reuse the
    /// exact FFT table instance used during generation. Noise, including trace
    /// amplification, key-switch and FFT errors, must fit the caller's budget.
    ///
    /// # Panics
    /// Panics before writes if input/output, FFT or workspace lengths do not match the key.
    pub fn apply_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_partial_to(input, 1, output, fft, context);
    }

    /// Retains `r=retained_coefficient_count` equally spaced message positions.
    /// With `d=N/r`, targets `d * sum_j M[j*d] X^(j*d)` in the original ring.
    /// `r=N` copies input; `r=1` is full trace.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key, representation and noise requirements.
    ///
    /// # Panics
    /// Inherits that method's resource checks. Also panics before writes unless
    /// `retained_coefficient_count` is a power-of-two divisor of N.
    pub fn apply_partial_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_batch(input.as_ref(), 1, output.as_ref(), fft, context);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, false>(output.as_mut(), levels, fft, context);
    }

    /// Applies full normalized reverse trace, targeting the constant message `M[0]`.
    /// Inherits [`Self::apply_reverse_partial_to`]'s numerical and panic contracts.
    pub fn apply_reverse_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_reverse_partial_to(input, 1, output, fft, context);
    }

    /// Applies normalized reverse trace to `r=retained_coefficient_count` positions.
    /// With `d=N/r`, targets `sum_j M[j*d] X^(j*d)` without changing ring degree.
    /// Keys are visited in ascending degree; `r=N` copies input.
    ///
    /// # Correctness
    /// Inherits [`Self::apply_to`]'s key and representation requirements.
    /// Each halving uses unsigned coefficient `floor(c/2)`, including wrapped
    /// negative representatives, before automorphism. It never divides complex
    /// Fourier values by two. The coefficient rounding error enters the phase
    /// multiplied by the NTRU secret f; bound it using that secret's coefficient
    /// norm, together with subsequent trace maps, FFT and key-switch errors.
    /// Non-target coefficients can retain residual noise. GLWE noise bounds
    /// cannot be reused without accounting for this multiplication by f.
    ///
    /// # Panics
    /// Inherits [`Self::apply_partial_to`]'s prewrite checks.
    pub fn apply_reverse_partial_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        retained_coefficient_count: usize,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let levels = kernels::check_count(self.poly_length(), retained_coefficient_count);
        self.check_batch(input.as_ref(), 1, output.as_ref(), fft, context);
        output.as_mut().copy_from_slice(input.as_ref());
        self.trace_kernel_assign::<_, true>(output.as_mut(), levels, fft, context);
    }

    /// Projects one coefficient to the constant position using a monomial shift
    /// followed by reverse trace. Inherits [`Self::project_coefficients_to`]'s
    /// numerical and prewrite checks; `index` must be below N.
    pub fn project_coefficient_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        index: usize,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.project_coefficients_to(input, &[index], output.as_mut(), fft, context);
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
    pub fn project_coefficients_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        indices: &[usize],
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        self.check_batch(input.as_ref(), indices.len(), output, fft, context);
        let n = self.poly_length();
        assert!(
            indices.iter().all(|&index| index < n),
            "projection index outside polynomial"
        );
        let modulus = NativeModulus::new();
        let exponents = PowOf2Modulus::new(2 * n);
        for (&index, output) in indices.iter().zip(output.chunks_exact_mut(n)) {
            input.mul_monomial_to(
                exponents.reduce_neg(index),
                &mut NtruCiphertext::new(&mut *output),
                modulus,
            );
            self.trace_kernel_assign::<_, true>(output, self.automorphism_count(), fft, context);
        }
    }

    /// Expands every coefficient to a constant-message NTRU in natural order.
    /// Equivalent to [`Self::expand_partial_coefficients_to`] with count=N,
    /// requiring no message zero-tail assumption. Output holds N*N coefficients.
    pub fn expand_coefficients_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        self.expand_partial_coefficients_to(input, self.poly_length(), output, fft, context);
    }

    /// Expands a message supported on its first `count` coefficients to `count`
    /// constant-message NTRUs in natural order, in the same N-coefficient ring.
    /// Uses output as tree storage and count-1 automorphisms without allocation.
    ///
    /// # Correctness
    /// The target message must be zero at every position >= count. Neither the
    /// ciphertext nor its noise needs a zero tail. A general message instead
    /// yields residue-class polynomials `sum_j M[i+j*count] X^(j*count)`.
    /// Inherits [`Self::apply_to`]'s representation requirements. Input is
    /// normalized once by unsigned integer division by count before the unscaled
    /// tree; rounding errors enter phase multiplied by f. This differs from
    /// reverse-trace projection and requires its own precision/noise budget.
    /// Non-target coefficients can contain noise.
    ///
    /// # Panics
    /// Panics before writes unless count is a power-of-two divisor of N,
    /// output has exactly count*N coefficients, and input/resources match the key.
    pub fn expand_partial_coefficients_to<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        kernels::check_count(self.poly_length(), count);
        self.check_batch(input.as_ref(), count, output, fft, context);
        if count == 1 {
            output.copy_from_slice(input.as_ref());
            return;
        }
        let log_count = count.trailing_zeros();
        let FourierNtruTraceContext {
            automorphism_output,
            automorphism,
        } = context;
        kernels::expand_to(
            input.as_ref(),
            output,
            automorphism_output.as_mut(),
            NativeModulus::new(),
            |values| {
                for value in values {
                    *value >>= log_count;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    &NtruCiphertext::new(input),
                    &mut NtruCiphertext::new(output),
                    fft,
                    automorphism,
                )
            },
        );
    }

    fn check_batch<Table: FftTable>(
        &self,
        input: &[T],
        count: usize,
        output: &[T],
        fft: &FftEngine<'_, Table>,
        context: &FourierNtruTraceContext<T>,
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
        self.automorphism_keys[0].assert_compatible(fft, &context.automorphism);
    }

    /// Requires checked operands/resources; all keys share one immutable domain.
    fn trace_kernel_assign<Table: FftTable, const REVERSE: bool>(
        &self,
        output: &mut [T],
        levels: usize,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruTraceContext<T>,
    ) {
        let FourierNtruTraceContext {
            automorphism_output,
            automorphism,
        } = context;
        kernels::trace_assign::<_, _, _, _, REVERSE>(
            output,
            levels,
            automorphism_output.as_mut(),
            NativeModulus::new(),
            |values| {
                for value in values {
                    *value >>= 1u32;
                }
            },
            |index, input, output| {
                self.automorphism_keys[index].apply_kernel_to(
                    &NtruCiphertext::new(input),
                    &mut NtruCiphertext::new(output),
                    fft,
                    automorphism,
                )
            },
        );
    }
}
