use aligned_vec::{AVec, avec};
use primus_data::DataMut;
use primus_factor::{FactorMul, MultiplyFactor, ShoupFactor};
use primus_gcd::Xgcd;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

#[cfg(target_arch = "x86_64")]
use crate::constants::{HAS_AVX2, HAS_AVX512DQ, HAS_AVX512IFMA};
use crate::{
    NttError,
    ntt::{MonomialNttTable, NttTable, assert_ntt_length},
    reverse::ReverseLsbs,
    root::PrimitiveRoot,
};

#[cfg(target_arch = "x86_64")]
use super::avx2::precompute::build_avx2_roots_u64;
#[cfg(target_arch = "x86_64")]
use super::avx512::internal::{IFMA_SHIFT_BITS, MAX_DQ32_MODULUS, MAX_IFMA_MODULUS};
use super::precompute::build_barrett_vector;

/// Backend-specific constants for the fused final inverse stage.
#[derive(Clone, Copy)]
pub(super) struct InverseFinalScale {
    pub(super) inv_n: u64,
    pub(super) inv_n_precon: u64,
    pub(super) inv_n_w: u64,
    pub(super) inv_n_w_precon: u64,
}

/// Exact transform kernel selected for `U64NttTable`.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum U64Backend {
    Scalar32,
    Scalar64,
    /// AVX2 backend using 64-bit Barrett multiplication.
    Avx2,
    /// AVX-512 DQ backend using 32-bit Barrett multiplication.
    Avx512Dq32,
    /// AVX-512 DQ backend using 64-bit Barrett multiplication.
    Avx512Dq64,
    /// AVX-512 IFMA backend using 52-bit Barrett multiplication.
    Avx512Ifma52,
}

#[cfg(target_arch = "x86_64")]
/// Selects one kernel that is valid for both forward and inverse transforms.
fn select_u64_backend(
    n: usize,
    q: u64,
    has_avx512_ifma: bool,
    has_avx512_dq: bool,
    has_avx2: bool,
) -> U64Backend {
    let low_q = q < (1u64 << 30);

    if n < 16 {
        return if low_q {
            U64Backend::Scalar32
        } else {
            U64Backend::Scalar64
        };
    }

    // IFMA and all DQ fallbacks require AVX-512DQ. A narrow Barrett width is
    // selected only when both transform directions support its modulus range.
    if has_avx512_ifma && has_avx512_dq && q < MAX_IFMA_MODULUS {
        U64Backend::Avx512Ifma52
    } else if has_avx512_dq {
        if q < MAX_DQ32_MODULUS {
            U64Backend::Avx512Dq32
        } else {
            U64Backend::Avx512Dq64
        }
    } else if has_avx2 && !low_q {
        U64Backend::Avx2
    } else if low_q {
        U64Backend::Scalar32
    } else {
        U64Backend::Scalar64
    }
}

/// Specialized NTT table for `u64` coefficients.
///
/// Stores canonical roots and only the preconditioners and packed forward-root
/// layout required by the backend selected at construction. Supports scalar,
/// AVX2, AVX-512 DQ, and AVX-512 IFMA kernels.
///
/// # Constraints
///
/// - `q < 2^62` — ensures lazy ranges `[0, 4q)` fit in `u64`.
#[derive(Clone)]
pub struct U64NttTable {
    pub(super) n: usize,
    log_n: u32,
    pub(super) q: u64,
    pub(super) two_q: u64,
    root: u64,
    inv_root: u64,

    pub(super) inverse_final_scale: InverseFinalScale,

    /// Forward roots in bit-reversed order (size `n`).
    pub(super) roots: AVec<u64>,
    /// Barrett-32 preconditioners for `roots` (scalar-32 path; empty otherwise).
    pub(super) roots_precon32: AVec<u64>,
    /// Barrett-64 preconditioners for `roots` (scalar-64/AVX2; empty otherwise).
    pub(super) roots_precon64: AVec<u64>,
    /// Inverse roots in bit-reversed order (size `n`).
    pub(super) inv_roots: AVec<u64>,
    /// Barrett-64 preconditioners for `inv_roots` (64-bit paths; empty otherwise).
    pub(super) inv_roots_precon64: AVec<u64>,

    // ── AVX2 pre-expanded tables ───────────────────────────────────────
    /// AVX2 forward roots pre-expanded for T2/T1 vector loads (size ≈ n).
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_roots: AVec<u64>,
    /// AVX2 forward precon pre-expanded for T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_roots_precon: AVec<u64>,
    /// AVX2 inverse roots pre-expanded for T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_inv_roots: AVec<u64>,
    /// AVX2 inverse precon pre-expanded for T2/T1 vector loads.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2_inv_roots_precon: AVec<u64>,

    // ── AVX-512 pre-expanded tables (hexl-compatible layout) ───────────
    /// AVX-512 forward roots (T8/T4/T2/T1 layout, size ≈ 13n/8).
    #[cfg(target_arch = "x86_64")]
    avx512_roots: AVec<u64>,
    /// Barrett-32 preconditioners for `avx512_roots` (DQ-32 forward).
    #[cfg(target_arch = "x86_64")]
    avx512_roots_precon32: AVec<u64>,
    /// Barrett-52 preconditioners for `avx512_roots` (IFMA forward).
    #[cfg(target_arch = "x86_64")]
    avx512_roots_precon52: AVec<u64>,
    /// Barrett-64 preconditioners for `avx512_roots` (DQ-64 forward).
    #[cfg(target_arch = "x86_64")]
    avx512_roots_precon64: AVec<u64>,

    /// Barrett-32 preconditioners for `inv_roots` (32-bit paths; empty otherwise).
    pub(super) inv_roots_precon32: AVec<u64>,
    /// Barrett-52 preconditioners for `inv_roots` (IFMA inverse).
    #[cfg(target_arch = "x86_64")]
    inv_roots_precon52: AVec<u64>,

    #[cfg(target_arch = "x86_64")]
    backend: U64Backend,
}

/// Compute the modular inverse of `a` modulo `q`.
///
/// Uses `primus_gcd::Xgcd::gcdinv`, which specializes quotients `1`, `2`, and
/// `3` before falling back to integer division.
fn mod_inv(a: u64, q: u64) -> u64 {
    let (inv, gcd) = u64::gcdinv(a, q);
    assert_eq!(gcd, 1, "a={a} is not invertible modulo q={q}");
    inv
}

impl U64NttTable {
    /// Returns `log2(N)`.
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    /// Returns the polynomial length `N`.
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the primitive `2N`-th root of unity.
    #[inline]
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Returns the inverse of the primitive root.
    #[inline]
    pub fn inv_root(&self) -> u64 {
        self.inv_root
    }

    /// Returns the inverse of `N` modulo `q`.
    #[inline]
    pub fn inv_n(&self) -> u64 {
        self.inverse_final_scale.inv_n
    }

    /// Dispatch forward transform to the selected backend.
    fn dispatch_forward(&self, values: &mut [u64], input_mod_factor: u32, output_mod_factor: u32) {
        assert_ntt_length(values.len(), self.n);

        #[cfg(target_arch = "x86_64")]
        {
            use super::avx512::transform::forward_transform_to_bit_reverse_avx512;

            match self.backend {
                U64Backend::Scalar32 => unsafe {
                    self.scalar_forward_transform_unchecked::<32>(values, output_mod_factor);
                },
                U64Backend::Scalar64 => unsafe {
                    self.scalar_forward_transform_unchecked::<64>(values, output_mod_factor);
                },
                U64Backend::Avx2 => unsafe {
                    self.avx2_forward_transform(values, output_mod_factor);
                },
                U64Backend::Avx512Dq32 => unsafe {
                    forward_transform_to_bit_reverse_avx512::<32>(
                        values,
                        self.q,
                        &self.avx512_roots,
                        &self.avx512_roots_precon32,
                        input_mod_factor as u64,
                        output_mod_factor as u64,
                        0,
                        0,
                    );
                },
                U64Backend::Avx512Dq64 => unsafe {
                    forward_transform_to_bit_reverse_avx512::<64>(
                        values,
                        self.q,
                        &self.avx512_roots,
                        &self.avx512_roots_precon64,
                        input_mod_factor as u64,
                        output_mod_factor as u64,
                        0,
                        0,
                    );
                },
                U64Backend::Avx512Ifma52 => unsafe {
                    forward_transform_to_bit_reverse_avx512::<{ IFMA_SHIFT_BITS }>(
                        values,
                        self.q,
                        &self.avx512_roots,
                        &self.avx512_roots_precon52,
                        input_mod_factor as u64,
                        output_mod_factor as u64,
                        0,
                        0,
                    );
                },
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = input_mod_factor;
            if self.q < (1u64 << 30) {
                unsafe {
                    self.scalar_forward_transform_unchecked::<32>(values, output_mod_factor);
                }
            } else {
                unsafe {
                    self.scalar_forward_transform_unchecked::<64>(values, output_mod_factor);
                }
            }
        }
    }

    /// Dispatch inverse transform to the selected backend.
    fn dispatch_inverse(&self, values: &mut [u64], input_mod_factor: u32, output_mod_factor: u32) {
        assert_ntt_length(values.len(), self.n);

        #[cfg(target_arch = "x86_64")]
        {
            use super::avx512::transform::inverse_transform_from_bit_reverse_avx512;

            match self.backend {
                U64Backend::Scalar32 => unsafe {
                    self.scalar_inverse_transform_unchecked::<32>(values, output_mod_factor);
                },
                U64Backend::Scalar64 => unsafe {
                    self.scalar_inverse_transform_unchecked::<64>(values, output_mod_factor);
                },
                U64Backend::Avx2 => unsafe {
                    self.avx2_inverse_transform(values, output_mod_factor);
                },
                U64Backend::Avx512Dq32 => unsafe {
                    inverse_transform_from_bit_reverse_avx512::<32>(
                        values,
                        self.q,
                        &self.inverse_final_scale,
                        &self.inv_roots,
                        &self.inv_roots_precon32,
                        input_mod_factor as u64,
                        output_mod_factor as u64,
                        0,
                        0,
                    );
                },
                U64Backend::Avx512Dq64 => unsafe {
                    inverse_transform_from_bit_reverse_avx512::<64>(
                        values,
                        self.q,
                        &self.inverse_final_scale,
                        &self.inv_roots,
                        &self.inv_roots_precon64,
                        input_mod_factor as u64,
                        output_mod_factor as u64,
                        0,
                        0,
                    );
                },
                U64Backend::Avx512Ifma52 => unsafe {
                    inverse_transform_from_bit_reverse_avx512::<{ IFMA_SHIFT_BITS }>(
                        values,
                        self.q,
                        &self.inverse_final_scale,
                        &self.inv_roots,
                        &self.inv_roots_precon52,
                        input_mod_factor as u64,
                        output_mod_factor as u64,
                        0,
                        0,
                    );
                },
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = input_mod_factor;
            if self.q < (1u64 << 30) {
                unsafe {
                    self.scalar_inverse_transform_unchecked::<32>(values, output_mod_factor);
                }
            } else {
                unsafe {
                    self.scalar_inverse_transform_unchecked::<64>(values, output_mod_factor);
                }
            }
        }
    }
}

impl NttTable for U64NttTable {
    type ValueT = u64;

    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let root = <u64 as PrimitiveRoot>::try_minimal_primitive_root(log_n + 1, modulus)?;
        let q = modulus.value();

        // Reject unsupported moduli: q < 2^62 required for lazy [0, 4q) range.
        if q >= 1 << crate::U64_NTT_MAX_MODULUS_BITS {
            return Err(NttError::ModulusTooLarge {
                modulus: q,
                max_bits: crate::U64_NTT_MAX_MODULUS_BITS,
            });
        }

        let n = 1usize << log_n;
        let two_q = q << 1;
        #[cfg(not(target_arch = "x86_64"))]
        let low_q = q < (1u64 << 30);

        #[cfg(target_arch = "x86_64")]
        let backend = select_u64_backend(n, q, *HAS_AVX512IFMA, *HAS_AVX512DQ, *HAS_AVX2);

        #[cfg(target_arch = "x86_64")]
        let use_roots_precon32 = matches!(backend, U64Backend::Scalar32);
        #[cfg(not(target_arch = "x86_64"))]
        let use_roots_precon32 = low_q;

        #[cfg(target_arch = "x86_64")]
        let use_roots_precon64 = matches!(backend, U64Backend::Scalar64 | U64Backend::Avx2);
        #[cfg(not(target_arch = "x86_64"))]
        let use_roots_precon64 = !low_q;

        #[cfg(target_arch = "x86_64")]
        let use_inv_roots_precon32 =
            matches!(backend, U64Backend::Scalar32 | U64Backend::Avx512Dq32);
        #[cfg(not(target_arch = "x86_64"))]
        let use_inv_roots_precon32 = low_q;

        #[cfg(target_arch = "x86_64")]
        let use_inv_roots_precon64 = matches!(
            backend,
            U64Backend::Scalar64 | U64Backend::Avx2 | U64Backend::Avx512Dq64
        );
        #[cfg(not(target_arch = "x86_64"))]
        let use_inv_roots_precon64 = !low_q;

        let inv_root = mod_inv(root, q);
        debug_assert_eq!(modulus.reduce_mul(root, inv_root), 1);

        // --- forward roots (bit-reversed) ---
        let root_sf = ShoupFactor::<u64>::new(root, q);
        let mut roots = avec![0u64; n];
        let mut power = 1;
        for i in 0..n {
            roots[i.reverse_lsbs(log_n)] = power;
            power = root_sf.factor_mul_modulo(power, q);
        }

        // --- inverse roots (bit-reversed, scrambled order) ---
        let inv_root_sf = ShoupFactor::<u64>::new(inv_root, q);
        let mut inv_roots = avec![0u64; n];
        inv_roots[0] = 1;
        let mut inv_power = inv_root;
        for i in 0..n - 1 {
            inv_roots[i.reverse_lsbs(log_n) + 1] = inv_power;
            inv_power = inv_root_sf.factor_mul_modulo(inv_power, q);
        }

        // --- backend-selected Shoup preconditioners ---
        let roots_precon32 = if use_roots_precon32 {
            build_barrett_vector(&roots, 32, q)
        } else {
            AVec::with_capacity(64, 0)
        };
        let roots_precon64 = if use_roots_precon64 {
            AVec::from_iter(
                64,
                roots
                    .iter()
                    .map(|&w| ShoupFactor::<u64>::quotient_for(w, q)),
            )
        } else {
            AVec::with_capacity(64, 0)
        };
        let inv_roots_precon32 = if use_inv_roots_precon32 {
            build_barrett_vector(&inv_roots, 32, q)
        } else {
            AVec::with_capacity(64, 0)
        };
        let inv_roots_precon64 = if use_inv_roots_precon64 {
            AVec::from_iter(
                64,
                inv_roots
                    .iter()
                    .map(|&w| ShoupFactor::<u64>::quotient_for(w, q)),
            )
        } else {
            AVec::with_capacity(64, 0)
        };

        // --- constants for the backend's fused final inverse stage ---
        #[cfg(target_arch = "x86_64")]
        let inverse_bit_shift = match backend {
            U64Backend::Scalar32 | U64Backend::Avx512Dq32 => 32,
            U64Backend::Avx512Ifma52 => IFMA_SHIFT_BITS,
            U64Backend::Scalar64 | U64Backend::Avx2 | U64Backend::Avx512Dq64 => 64,
        };
        #[cfg(not(target_arch = "x86_64"))]
        let inverse_bit_shift = if low_q { 32 } else { 64 };

        let inv_n = mod_inv(n as u64, q);
        let last_w = unsafe { *inv_roots.get_unchecked(n - 1) };
        let inv_n_w = modulus.reduce_mul(inv_n, last_w);
        let inverse_final_scale = InverseFinalScale {
            inv_n,
            inv_n_precon: MultiplyFactor::new(inv_n, inverse_bit_shift, q).quotient(),
            inv_n_w,
            inv_n_w_precon: MultiplyFactor::new(inv_n_w, inverse_bit_shift, q).quotient(),
        };

        // --- backend-specific pre-expanded root tables ---
        #[cfg(target_arch = "x86_64")]
        let use_avx2 = matches!(backend, U64Backend::Avx2);
        #[cfg(target_arch = "x86_64")]
        let (avx2_roots, avx2_roots_precon, avx2_inv_roots, avx2_inv_roots_precon) = if use_avx2 {
            (
                build_avx2_roots_u64(n, &roots, false),
                build_avx2_roots_u64(n, &roots_precon64, false),
                build_avx2_roots_u64(n, &inv_roots, true),
                build_avx2_roots_u64(n, &inv_roots_precon64, true),
            )
        } else {
            (
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
                AVec::with_capacity(64, 0),
            )
        };

        #[cfg(target_arch = "x86_64")]
        let use_avx512 = matches!(
            backend,
            U64Backend::Avx512Dq32 | U64Backend::Avx512Dq64 | U64Backend::Avx512Ifma52
        );
        #[cfg(target_arch = "x86_64")]
        let avx512_roots = if use_avx512 {
            super::avx512::precompute::build_avx512_root_powers(n, &roots)
        } else {
            AVec::with_capacity(64, 0)
        };
        #[cfg(target_arch = "x86_64")]
        let avx512_roots_precon32 = if matches!(backend, U64Backend::Avx512Dq32) {
            build_barrett_vector(&avx512_roots, 32, q)
        } else {
            AVec::with_capacity(64, 0)
        };
        #[cfg(target_arch = "x86_64")]
        let avx512_roots_precon52 = if matches!(backend, U64Backend::Avx512Ifma52) {
            build_barrett_vector(&avx512_roots, 52, q)
        } else {
            AVec::with_capacity(64, 0)
        };
        #[cfg(target_arch = "x86_64")]
        let avx512_roots_precon64 = if matches!(backend, U64Backend::Avx512Dq64) {
            build_barrett_vector(&avx512_roots, 64, q)
        } else {
            AVec::with_capacity(64, 0)
        };
        #[cfg(target_arch = "x86_64")]
        let inv_roots_precon52 = if matches!(backend, U64Backend::Avx512Ifma52) {
            build_barrett_vector(&inv_roots, 52, q)
        } else {
            AVec::with_capacity(64, 0)
        };

        Ok(Self {
            n,
            log_n,
            q,
            two_q,
            root,
            inv_root,
            inverse_final_scale,
            roots,
            roots_precon32,
            roots_precon64,
            inv_roots,
            inv_roots_precon64,
            #[cfg(target_arch = "x86_64")]
            avx2_roots,
            #[cfg(target_arch = "x86_64")]
            avx2_roots_precon,
            #[cfg(target_arch = "x86_64")]
            avx2_inv_roots,
            #[cfg(target_arch = "x86_64")]
            avx2_inv_roots_precon,
            #[cfg(target_arch = "x86_64")]
            avx512_roots,
            #[cfg(target_arch = "x86_64")]
            avx512_roots_precon32,
            #[cfg(target_arch = "x86_64")]
            avx512_roots_precon52,
            #[cfg(target_arch = "x86_64")]
            avx512_roots_precon64,
            inv_roots_precon32,
            #[cfg(target_arch = "x86_64")]
            inv_roots_precon52,
            #[cfg(target_arch = "x86_64")]
            backend,
        })
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.n
    }

    #[inline]
    fn modulus(&self) -> Self::ValueT {
        self.q
    }

    #[inline]
    fn transform_inplace<S: DataMut<Elem = Self::ValueT>>(
        &self,
        mut poly: Polynomial<S>,
    ) -> NttPolynomial<S> {
        self.transform_slice(poly.as_mut_slice());
        NttPolynomial::new(poly.0)
    }

    #[inline]
    fn inverse_transform_inplace<S: DataMut<Elem = Self::ValueT>>(
        &self,
        mut values: NttPolynomial<S>,
    ) -> Polynomial<S> {
        self.inverse_transform_slice(values.as_mut_slice());
        Polynomial::new(values.0)
    }

    #[inline]
    fn lazy_transform_slice(&self, poly: &mut [u64]) {
        self.dispatch_forward(poly, 4, 4);
    }

    #[inline]
    fn transform_slice(&self, poly: &mut [u64]) {
        self.dispatch_forward(poly, 1, 1);
    }

    #[inline]
    fn lazy_inverse_transform_slice(&self, values: &mut [u64]) {
        self.dispatch_inverse(values, 2, 2);
    }

    #[inline]
    fn inverse_transform_slice(&self, values: &mut [u64]) {
        self.dispatch_inverse(values, 1, 1);
    }
}

impl MonomialNttTable for U64NttTable {
    #[inline]
    fn root_powers(&self) -> &[Self::ValueT] {
        &self.roots
    }

    #[inline]
    fn inv_root_powers(&self) -> &[Self::ValueT] {
        &self.inv_roots
    }
}
