use primus_data::DataMut;
use primus_factor::{FactorMul, LazyFactorMul, ShoupFactor};
use primus_integer::FheUint;
use primus_modulus::common::compact;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{NttError, reverse::ReverseLsbs, root::PrimitiveRoot};

use super::{MonomialNttTable, NttTable, assert_ntt_length};

/// This struct store the pre-computed data for number theory transform and
/// inverse number theory transform.
///
/// ## The structure members meet the following conditions:
///
/// 1. `n = 1 << log_n`
/// 1. `root^{n} ≡ -1 (mod modulus)`
/// 1. `root * inv_root ≡ 1 (mod modulus)`
/// 1. `n * inv_n ≡ 1 (mod modulus)`
/// 1. `root_powers` holds 0~(n-1)-th powers of root in bit-reversed order.
/// 1. `inv_root_powers` holds 0~(n-1)-th powers of inverse root in scrambled order.
/// 1. Root values and their Shoup preconditioners use separate, equally sized arrays.
///
/// ## Compare three orders:
///
/// ```plain
/// normal order:        0  1  2  3  4  5  6  7
///
/// bit-reversed order:  0  4  2  6  1  5  3  7
///                         -  ----  ----------
/// scrambled order:     0  1  5  3  7  2  6  4
///                         ----------  ----  -
/// ```
///
/// # Constraints
///
/// The modulus must satisfy `1 < modulus < 2^(T::BITS - 2)` so every lazy
/// intermediate in `[0, 4 * modulus)` is representable by `T`.
pub struct UintNttTable<T: FheUint> {
    root: T,
    inv_root: T,
    modulus: T,
    log_n: u32,
    n: usize,
    inv_n: ShoupFactor<T>,
    /// `inv_n * inv_root_powers[n-1] mod q` — precomputed for the inverse final stage.
    inv_n_r: ShoupFactor<T>,
    root_powers: Vec<T>,
    root_powers_precon: Vec<T>,
    inv_root_powers: Vec<T>,
    inv_root_powers_precon: Vec<T>,
}

impl<T: FheUint> UintNttTable<T> {
    /// Returns the root of this [`UintNttTable<T>`].
    #[inline]
    pub fn root(&self) -> T {
        self.root
    }

    /// Returns the inverse element of the root of this [`UintNttTable<T>`].
    #[inline]
    pub fn inv_root(&self) -> T {
        self.inv_root
    }

    /// Returns the modulus of this [`UintNttTable<T>`].
    #[inline]
    pub fn modulus(&self) -> T {
        self.modulus
    }

    /// Returns the log n of this [`UintNttTable<T>`].
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }

    /// Returns the n of this [`UintNttTable<T>`].
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the inverse element of the n of this [`UintNttTable<T>`].
    #[inline]
    pub fn inv_n(&self) -> ShoupFactor<T> {
        self.inv_n
    }

    /// Returns `inv_n * inv_root_powers[n-1] mod q` — precomputed for the inverse final stage..
    #[inline]
    pub fn inv_n_r(&self) -> ShoupFactor<T> {
        self.inv_n_r
    }

    /// Returns a reference to the root powers of this [`UintNttTable<T>`].
    #[inline]
    pub fn root_powers(&self) -> &[T] {
        &self.root_powers
    }

    /// Returns the Shoup preconditioners for [`Self::root_powers`].
    #[inline]
    pub fn root_powers_precon(&self) -> &[T] {
        &self.root_powers_precon
    }

    /// Returns a reference to the inverse elements of the root powers of this [`UintNttTable<T>`].
    #[inline]
    pub fn inv_root_powers(&self) -> &[T] {
        &self.inv_root_powers
    }

    /// Returns the Shoup preconditioners for [`Self::inv_root_powers`].
    #[inline]
    pub fn inv_root_powers_precon(&self) -> &[T] {
        &self.inv_root_powers_precon
    }
}

impl<T: FheUint> NttTable for UintNttTable<T> {
    type ValueT = T;

    #[inline]
    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let modulus_value = modulus.value();
        let max_bits = T::BITS - crate::NTT_LAZY_REDUCTION_HEADROOM_BITS;
        if modulus_value >= T::ONE << max_bits {
            return Err(NttError::ModulusTooLarge {
                modulus: modulus_value,
                max_bits,
            });
        }

        let root = <T as PrimitiveRoot>::try_minimal_primitive_root(log_n + 1, modulus)?;
        let modulus = modulus_value;

        let n = 1usize << log_n;
        let to_root_type = |x| -> ShoupFactor<T> { <ShoupFactor<T>>::new(x, modulus) };

        let root_factor = to_root_type(root);
        let inv_root = compact::reduce_inv(modulus, root);

        debug_assert_eq!(root_factor.factor_mul_modulo(inv_root, modulus), T::ONE);

        let mut root_powers = vec![T::ZERO; n];
        let mut power = T::ONE;
        for i in 0..n {
            root_powers[i.reverse_lsbs(log_n)] = power;
            power = root_factor.factor_mul_modulo(power, modulus);
        }
        let root_powers_precon = root_powers
            .iter()
            .map(|&root| ShoupFactor::quotient_for(root, modulus))
            .collect();

        let inv_root_factor = to_root_type(inv_root);
        let mut inv_root_powers = vec![T::ZERO; n];
        inv_root_powers[0] = T::ONE;
        let mut inv_power = inv_root;
        for i in 0..n - 1 {
            inv_root_powers[i.reverse_lsbs(log_n) + 1] = inv_power;
            inv_power = inv_root_factor.factor_mul_modulo(inv_power, modulus);
        }
        let inv_root_powers_precon = inv_root_powers
            .iter()
            .map(|&root| ShoupFactor::quotient_for(root, modulus))
            .collect::<Vec<_>>();

        let n_cast =
            T::try_from(n).map_err(|_| NttError::DegreeConversionErr { degree: n, modulus })?;

        if n_cast >= modulus {
            return Err(NttError::DegreeTooLarge { degree: n, modulus });
        }

        let inv_n = to_root_type(compact::reduce_inv(modulus, n_cast));

        let inv_n_r = ShoupFactor::from_raw(
            *inv_root_powers.last().unwrap(),
            *inv_root_powers_precon.last().unwrap(),
        )
        .factor_mul_modulo(inv_n.value(), modulus);
        let inv_n_r = ShoupFactor::new(inv_n_r, modulus);

        Ok(Self {
            root,
            inv_root,
            modulus,
            log_n,
            n,
            inv_n,
            inv_n_r,
            root_powers,
            root_powers_precon,
            inv_root_powers,
            inv_root_powers_precon,
        })
    }

    #[inline(always)]
    fn poly_length(&self) -> usize {
        self.n
    }

    #[inline]
    fn modulus(&self) -> Self::ValueT {
        self.modulus
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
    fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        assert_ntt_length(poly.len(), self.n);

        let modulus = self.modulus();
        let twice_modulus = modulus << 1u32;

        let roots = self.root_powers();
        let roots_precon = self.root_powers_precon();
        let mut root_index = 1usize;

        for gap in (0..self.log_n).rev().map(|x| 1usize << x) {
            for vc in poly.chunks_exact_mut(gap << 1) {
                // The transform consumes roots 1..N exactly once.
                let root = unsafe {
                    ShoupFactor::from_raw(
                        *roots.get_unchecked(root_index),
                        *roots_precon.get_unchecked(root_index),
                    )
                };
                root_index += 1;
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = compact::reduce_once(twice_modulus, *i);
                    let v = root.lazy_factor_mul_modulo(*j, modulus);
                    *i = u + v;
                    *j = u + twice_modulus - v;
                }
            }
        }
    }

    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_transform_slice(poly);

        let modulus = self.modulus();
        let twice_modulus = modulus << 1u32;
        poly.iter_mut().for_each(|v| {
            *v = compact::reduce_once(modulus, compact::reduce_once(twice_modulus, *v));
        });
    }

    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        assert_ntt_length(values.len(), self.n);

        let log_n = self.log_n;

        let modulus = self.modulus();
        let twice_modulus = modulus << 1u32;

        let roots = self.inv_root_powers();
        let roots_precon = self.inv_root_powers_precon();
        let mut root_index = 1usize;

        for gap in (0..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                // The non-final stages consume roots 1..N/2 exactly once.
                let root = unsafe {
                    ShoupFactor::from_raw(
                        *roots.get_unchecked(root_index),
                        *roots_precon.get_unchecked(root_index),
                    )
                };
                root_index += 1;
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = *i;
                    let v = *j;
                    *i = compact::reduce_add(twice_modulus, u, v);
                    *j = root.lazy_factor_mul_modulo(u + twice_modulus - v, modulus);
                }
            }
        }

        let gap = 1 << (log_n - 1);

        let scalar = self.inv_n();
        let scaled_r = self.inv_n_r();

        let (v0, v1) = values.split_at_mut(gap);
        for (i, j) in core::iter::zip(v0, v1) {
            let u = *i;
            let v = *j;
            *i = scalar.factor_mul_modulo(u + v, modulus);
            *j = scaled_r.factor_mul_modulo(u + twice_modulus - v, modulus);
        }
    }

    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_inverse_transform_slice(values);

        let modulus = self.modulus();
        values.iter_mut().for_each(|v| {
            compact::reduce_once_assign(modulus, v);
        });
    }
}

impl<T: FheUint> MonomialNttTable for UintNttTable<T> {
    #[inline]
    fn root_powers(&self) -> &[Self::ValueT] {
        &self.root_powers
    }

    #[inline]
    fn inv_root_powers(&self) -> &[Self::ValueT] {
        &self.inv_root_powers
    }
}
