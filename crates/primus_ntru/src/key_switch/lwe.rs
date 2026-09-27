//! Coefficient-domain NTRU to independent LWE key switching with modulus conversion.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::{FheUint, SignedInteger};
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweKeySwitchingKey, LweParameters, LweSecretKey, LweSecretKeyRef};
use primus_modulus::ModulusSwitch;
use primus_reduce::{Modulus, PreparedModulusSwitch, RingContext};

use crate::{NtruCiphertext, NtruSecretKey};

/// Switches a coefficient of `f*c` at modulus Q to an independent LWE key at q.
///
/// Evaluation rounds each NTRU coefficient from Q to q, extracts an LWE under
/// the signed coefficient vector of f, then uses an ordinary LWE key switch at q.
/// The target secret has an independent dimension and need not be NTRU-invertible.
/// No NTT/FFT table is needed; transformed ciphertexts must first be recovered to
/// coefficients. Source and target share the integer type T (no word-width cast).
/// Both moduli may be native or explicit, including Q = q.
#[derive(Clone)]
pub struct NtruLweKeySwitchingKey<T: FheUint> {
    input_modulus: Option<T>,
    modulus_switch: ModulusSwitch<T>,
    key_switch: LweKeySwitchingKey<T>,
}

impl<T: FheUint> NtruLweKeySwitchingKey<T> {
    /// Generates LWE encryptions of the gadget-scaled signed coefficients of f at q.
    ///
    /// `input_modulus` fixes Q; `output_parameters` and `basis` fix q. Secret
    /// coefficients are borrowed directly; no converted copy of f is retained.
    ///
    /// # Panics
    /// Panics before sampling if an explicit Q is below two, a coefficient of f
    /// has magnitude at least an explicit q, or the dimensions/basis violate
    /// [`LweKeySwitchingKey::generate`]'s checks. Key storage overflow also panics.
    ///
    /// # Correctness
    /// Output secret coefficients inherit [`LweKeySwitchingKey::generate`]'s
    /// canonical-residue requirement at q. The input ciphertext must use f and Q;
    /// neither secret identity nor invertibility is checked by this conversion.
    pub fn generate<S, M, R>(
        input_secret_key: &NtruSecretKey<T>,
        input_modulus: S,
        output_secret_key: &LweSecretKey<T>,
        output_parameters: &LweParameters<T, M>,
        basis: ApproxSignedBasis<T>,
        rng: &mut R,
    ) -> Self
    where
        S: Modulus<ValueT = T>,
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let output_modulus = output_parameters.cipher_modulus();
        let modulus_switch = ModulusSwitch::new(input_modulus, output_modulus);
        if let Some(q) = output_modulus.explicit_value() {
            assert!(
                input_secret_key
                    .as_slice()
                    .iter()
                    .all(|&s| s.unsigned_abs() < q),
                "NTRU secret coefficient magnitude must be less than the target LWE modulus"
            );
        }
        let key_switch = LweKeySwitchingKey::generate(
            LweSecretKeyRef::Signed(input_secret_key.as_slice()),
            output_secret_key,
            output_parameters,
            basis,
            rng,
        );
        Self {
            input_modulus: input_modulus.explicit_value(),
            modulus_switch,
            key_switch,
        }
    }

    /// Returns the input NTRU polynomial length and intermediate LWE dimension.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.key_switch.input_dimension()
    }

    /// Returns Q, or `None` for the native modulus `2^T::BITS`.
    #[must_use]
    pub fn input_modulus(&self) -> Option<T> {
        self.input_modulus
    }

    /// Returns the independent target LWE dimension.
    #[must_use]
    pub fn output_dimension(&self) -> usize {
        self.key_switch.output_dimension()
    }

    /// Returns the target-q key-switch decomposition basis.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.key_switch.basis()
    }

    /// Returns `[coefficient of f][level][target LWE mask...,body]` storage at q.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.key_switch.as_slice()
    }

    /// Switches the constant coefficient of the NTRU phase into `output`.
    ///
    /// Inherits [`Self::key_switch_at_to`]'s correctness and prewrite checks,
    /// using coefficient index zero. Does not allocate.
    pub fn key_switch_to<M, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut Lwe<B>,
        modulus: M,
        context: &mut NtruLweKeySwitchingContext<T>,
    ) where
        M: RingContext<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.key_switch_at_to(input, 0, output, modulus, context);
    }

    /// Switches coefficient `index` of the NTRU phase into an LWE at q.
    ///
    /// With `c' = round(q*c/Q) mod q`, the intermediate mask is
    /// `a[i] = -c'[index-i]` for `i <= index`, otherwise `c'[N+index-i]`;
    /// `b = 0`. Its phase `b-<a,f>` equals `(f*c')[index]`.
    /// Rounding is nearest with ties upward, including endpoint wrap to zero.
    /// Modulus conversion precedes the extraction sign; reversing that order
    /// can change results at ties. Both steps write one preallocated LWE buffer.
    /// Output and scratch are overwritten; no reset or allocation is required.
    ///
    /// # Correctness
    /// Input is a coefficient-domain ciphertext under f with canonical residues
    /// at the generation-time Q. `modulus` supplies q. The phase approximates
    /// `(q/Q)*(f*c)[index]` modulo q: coefficient rounding is weighted by f,
    /// followed by secret-weighted decomposition error and key-entry noise.
    /// These errors and any previous NTRU/FFT error need a joint decoding budget.
    /// This operation does not decode or re-encode plaintexts.
    ///
    /// # Panics
    /// Panics before modifying output or scratch if input/output/context lengths,
    /// index, or the target modulus do not match this key.
    pub fn key_switch_at_to<M, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        index: usize,
        output: &mut Lwe<B>,
        modulus: M,
        context: &mut NtruLweKeySwitchingContext<T>,
    ) where
        M: RingContext<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let n = self.poly_length();
        assert_eq!(input.as_ref().len(), n, "NTRU input length mismatch");
        assert!(index < n, "NTRU extraction index is out of range");
        assert_eq!(
            output.as_ref().len(),
            self.output_dimension() + 1,
            "target LWE ciphertext length mismatch"
        );
        assert_eq!(
            context.poly_length(),
            n,
            "NTRU to LWE workspace length mismatch"
        );
        assert_eq!(
            modulus.explicit_value(),
            self.basis().modulus(),
            "target LWE modulus mismatch"
        );

        let coefficients = input.as_ref();
        let (mask, body) = context.extracted.a_b_mut();
        *body = T::ZERO;
        let (negative, wrapped) = mask.split_at_mut(index + 1);
        // Switch unsigned coefficients before applying the extraction sign.
        self.modulus_switch.switch_map(
            coefficients[..=index].iter().rev().copied().zip(negative),
            |value, out| *out = modulus.reduce_neg(value),
        );
        self.modulus_switch.switch_map(
            coefficients[index + 1..].iter().rev().copied().zip(wrapped),
            |value, out| *out = value,
        );
        self.key_switch
            .key_switch_to(&context.extracted, output, modulus);
    }
}

/// Reusable coefficient workspace for NTRU to LWE conversion.
///
/// Owns one `N+1`-element intermediate LWE at q. It contains only ciphertext
/// coefficients and no secret-key data. Each evaluation overwrites all entries.
pub struct NtruLweKeySwitchingContext<T: FheUint> {
    extracted: Lwe<Vec<T>>,
}

impl<T: FheUint> NtruLweKeySwitchingContext<T> {
    /// Allocates workspace for an input NTRU polynomial of length N.
    ///
    /// # Panics
    /// Panics if N is zero or `N+1` overflows `usize`.
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        assert!(poly_length > 0, "NTRU polynomial length must be nonzero");
        poly_length
            .checked_add(1)
            .expect("NTRU to LWE workspace length overflow");
        Self {
            extracted: Lwe::zero(poly_length),
        }
    }

    /// Returns the input NTRU polynomial length this workspace supports.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.extracted.dimension()
    }
}
