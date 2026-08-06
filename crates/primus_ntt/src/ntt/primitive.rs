use primus_data::{DataMut, RawData};
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
/// 1. `root_powers` holds 1~(n-1)-th powers of root in bit-reversed order, the 0-th power is left unset.
/// 1. `inv_root_powers` holds 1~(n-1)-th powers of inverse root in scrambled order, the 0-th power is left unset.
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
    root_powers: Vec<ShoupFactor<T>>,
    inv_root_powers: Vec<ShoupFactor<T>>,
    ordinal_root_powers: Vec<T>,
    reverse_lsbs: Vec<usize>,
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
    pub fn root_powers(&self) -> &[ShoupFactor<T>] {
        &self.root_powers
    }

    /// Returns a reference to the inverse elements of the root powers of this [`UintNttTable<T>`].
    #[inline]
    pub fn inv_root_powers(&self) -> &[ShoupFactor<T>] {
        &self.inv_root_powers
    }

    /// Returns a reference to the ordinal root powers of this [`UintNttTable<T>`].
    #[inline]
    pub fn ordinal_root_powers(&self) -> &[T] {
        &self.ordinal_root_powers
    }

    /// Returns a reference to the reverse lsbs of this [`UintNttTable<T>`].
    #[inline]
    pub fn reverse_lsbs(&self) -> &[usize] {
        &self.reverse_lsbs
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

        let root_one = to_root_type(T::ONE);
        let root_factor = to_root_type(root);

        let mut power = root;

        let mut ordinal_root_powers = vec![T::ZERO; n * 2];
        let mut iter = ordinal_root_powers.iter_mut();
        *iter.next().unwrap() = T::ONE;
        *iter.next().unwrap() = root;
        for root_power in iter {
            power = root_factor.factor_mul_modulo(power, modulus);
            *root_power = power;
        }

        let inv_root = *ordinal_root_powers.last().unwrap();

        debug_assert_eq!(root_factor.factor_mul_modulo(inv_root, modulus), T::ONE);

        let reverse_lsbs: Vec<usize> = (0..n).map(|i| i.reverse_lsbs(log_n)).collect();

        let mut root_powers = vec![<ShoupFactor<T>>::default(); n];
        root_powers[0] = root_one;
        for (&root_power, &i) in ordinal_root_powers[0..n].iter().zip(reverse_lsbs.iter()) {
            root_powers[i] = to_root_type(root_power);
        }

        let mut inv_root_powers = vec![<ShoupFactor<T>>::default(); n];
        inv_root_powers[0] = root_one;
        for (&inv_root_power, &i) in ordinal_root_powers[n + 1..]
            .iter()
            .rev()
            .zip(reverse_lsbs.iter())
        {
            inv_root_powers[i + 1] = to_root_type(inv_root_power);
        }

        let n_cast =
            T::try_from(n).map_err(|_| NttError::DegreeConversionErr { degree: n, modulus })?;

        if n_cast >= modulus {
            return Err(NttError::DegreeTooLarge { degree: n, modulus });
        }

        let inv_n = to_root_type(compact::reduce_inv(modulus, n_cast));

        let inv_n_r = inv_root_powers
            .last()
            .unwrap()
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
            inv_root_powers,
            ordinal_root_powers,
            reverse_lsbs,
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
    fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        mut poly: Polynomial<S>,
    ) -> NttPolynomial<S> {
        self.transform_slice(poly.as_mut_slice());
        NttPolynomial::new(poly.0)
    }

    #[inline]
    fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
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
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..self.log_n).rev().map(|x| 1usize << x) {
            for vc in poly.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
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
        let mut root_iter = roots[1..].iter().copied();

        for gap in (0..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                let root = root_iter.next().unwrap();
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
    fn ordinal_root_powers(&self) -> &[Self::ValueT] {
        &self.ordinal_root_powers
    }

    #[inline]
    fn reverse_lsbs(&self) -> &[usize] {
        &self.reverse_lsbs
    }
}
