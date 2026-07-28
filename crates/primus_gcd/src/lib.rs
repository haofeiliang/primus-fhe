//! Extended GCD and modular inverse for unsigned integer types.
//!
//! This implementation refers to the following codebases.
//! <https://flintlib.org/doc/ulong_extras.html#c.n_xgcd>
//! <https://flintlib.org/doc/ulong_extras.html#c.n_gcdinv>

#![deny(missing_docs)]

/// Lookup table for the modular inverse of an odd `u8` modulo `2^8`.
///
/// `INV_TABLE[((a >> 1) & 0x7F)]` gives the 8-bit inverse of the odd 8-bit
/// number whose lower 8 bits equal those of `a`.  It seeds the Hensel
/// iteration at 8 correct bits instead of 1, removing the first 3 steps.
///
/// Computed from the identity:
///   `INV_TABLE[i] ≡ (2i + 1)^(-1)  (mod 2^8)`   for `i ∈ [0,127]`.
const INV_TABLE: [u8; 128] = [
    1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19, 53, 223, 225, 139, 173, 151, 25,
    131, 165, 207, 209, 251, 29, 135, 9, 243, 21, 191, 193, 107, 141, 119, 249, 99, 133, 175, 177,
    219, 253, 103, 233, 211, 245, 159, 161, 75, 109, 87, 217, 67, 101, 143, 145, 187, 221, 71, 201,
    179, 213, 127, 129, 43, 77, 55, 185, 35, 69, 111, 113, 155, 189, 39, 169, 147, 181, 95, 97, 11,
    45, 23, 153, 3, 37, 79, 81, 123, 157, 7, 137, 115, 149, 63, 65, 235, 13, 247, 121, 227, 5, 47,
    49, 91, 125, 231, 105, 83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93, 199, 73,
    51, 85, 255,
];

/// Greatest common divisor and Bézout coefficients
pub trait Xgcd: Sized {
    /// Calculates the Greatest Common Divisor (GCD) of the number and `other`. The
    /// result is always non-negative.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// assert_eq!(42u64.gcd(56), 14);
    /// assert_eq!(0u64.gcd(5), 5);
    /// assert_eq!(5u64.gcd(0), 5);
    /// ```
    #[must_use]
    fn gcd(self, other: Self) -> Self;

    /// Check whether two numbers are coprime.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// assert!(14u64.is_coprime(25));
    /// assert!(!14u64.is_coprime(28));
    /// assert!(!0u64.is_coprime(0));
    /// ```
    #[must_use]
    #[allow(clippy::wrong_self_convention)]
    fn is_coprime(self, other: Self) -> bool;

    /// Returns `(a, b, g)`, where `g` is the greatest common divisor of `x`
    /// and `y`, and the unsigned coefficients satisfy `a x - b y = g` over
    /// the integers. Requires `x >= y`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// let (a, b, d) = u64::xgcd(240, 46);
    /// assert_eq!(d, 2);
    /// assert_eq!(a as u128 * 240 - b as u128 * 46, 2);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `x < y`.
    ///
    /// # Algorithm
    ///
    /// Uses the extended Euclidean algorithm, with the coefficient signs
    /// normalized to the returned form `a x - b y = g`.
    #[must_use]
    fn xgcd(x: Self, y: Self) -> (Self, Self, Self);

    /// Returns `(a, g)`, where `g = gcd(x, m)`, `0 <= a < m`, and
    /// `a x ≡ g (mod m)`. Requires `x < m`.
    ///
    /// When `g = 1`, `a` is the multiplicative inverse of `x` modulo `m`.
    ///
    /// When `m = 1` the greatest common divisor is set to `1` and `a` is
    /// set to `0`.
    ///
    /// This is merely an adaption of the extended Euclidean algorithm
    /// computing just one cofactor and reducing it modulo `m`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// let (a, d) = u64::gcdinv(17, 29);
    /// assert_eq!(d, 1);
    /// assert_eq!((a as u128 * 17) % 29, 1);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `x >= m`.
    #[must_use]
    fn gcdinv(x: Self, m: Self) -> (Self, Self);

    /// Computes the modular inverse of `a` modulo a power of two.
    ///
    /// The modulus is `mask + 1`, where `mask` must be of the form `2^k - 1`
    /// for `1 <= k <= Self::BITS`. Returns `None` if `a` is even, since no
    /// inverse exists modulo a nontrivial power of two for even numbers.
    ///
    /// Uses Newton's method (Hensel lifting):
    /// `x_{n+1} = x_n · (2 - a · x_n)  (mod 2^{2^n})`.
    ///
    /// The iteration doubles the number of correct bits each step, converging
    /// in O(log BITS) iterations.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// // modulus = 256, mask = 255
    /// let inv = u64::gcdinv_pow_of_2(3, 255).unwrap();
    /// assert_eq!((inv * 3) & 255, 1);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `mask` is zero or is not of the form `2^k - 1`.
    #[must_use]
    fn gcdinv_pow_of_2(a: Self, mask: Self) -> Option<Self>;

    /// Computes the modular inverse of `a` modulo `2^BITS` (the full native
    /// word size). Returns `None` if `a` is even.
    ///
    /// Equivalent to `gcdinv_pow_of_2(a, Self::MAX)`, but may avoid an
    /// explicit mask operation.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// let inv = u64::gcdinv_native(3).unwrap();
    /// assert_eq!(inv.wrapping_mul(3), 1);
    /// ```
    #[must_use]
    fn gcdinv_native(a: Self) -> Option<Self>;
}

macro_rules! impl_extended_gcd {
    (impl Xgcd for $SelfT:ty; SignedType: $SignedT:ty) => {
        // Anonymous const block scopes the helper fns so they are reachable
        // from both `xgcd` and `gcdinv` without polluting the module namespace
        // or colliding across the macro's multiple expansions.
        const _: () = {
            // Coefficient recurrences intentionally use limb-width wrapping,
            // matching FLINT's unsigned casts while staying valid in debug builds.
            #[inline]
            fn coeff_sub(lhs: $SignedT, rhs: $SignedT) -> $SignedT {
                lhs.wrapping_sub(rhs)
            }

            #[inline]
            fn coeff_sub_mul(lhs: $SignedT, factor: $SignedT, rhs: $SignedT) -> $SignedT {
                lhs.wrapping_sub(factor.wrapping_mul(rhs))
            }

            impl Xgcd for $SelfT {
                #[inline]
                fn gcd(self, other: Self) -> Self {
                    // Use Stein's algorithm
                    let mut m = self;
                    let mut n = other;
                    if m == 0 || n == 0 {
                        return m | n;
                    }

                    // find common factors of 2
                    let shift = (m | n).trailing_zeros();

                    // divide n and m by 2 until odd
                    m >>= m.trailing_zeros();
                    n >>= n.trailing_zeros();

                    while m != n {
                        if m > n {
                            m -= n;
                            m >>= m.trailing_zeros();
                        } else {
                            n -= m;
                            n >>= n.trailing_zeros();
                        }
                    }
                    m << shift
                }

                #[inline]
                fn is_coprime(self, other: Self) -> bool {
                    // Fast paths that avoid computing the full GCD.
                    if self == other {
                        return self == 1;
                    }
                    if self == 1 || other == 1 {
                        return true;
                    }
                    self.gcd(other) == 1
                }

                #[inline]
                fn xgcd(x: Self, y: Self) -> (Self, Self, Self) {
                    let mut u1: $SignedT;
                    let mut u2: $SignedT;
                    let mut v1: $SignedT;
                    let mut v2: $SignedT;
                    let mut t1: $SignedT;
                    let mut t2: $SignedT;

                    let mut u3: Self;
                    let mut v3: Self;
                    let mut quot: Self;
                    let mut rem: Self;
                    let mut d: Self;

                    assert!(x >= y);

                    u1 = 1;
                    v2 = 1;
                    u2 = 0;
                    v1 = 0;
                    u3 = x;
                    v3 = y;

                    // x and y both have top bit set
                    if ((x & y) as $SignedT) < 0 {
                        d = u3 - v3;
                        t2 = v2;
                        t1 = u2;
                        u2 = coeff_sub(u1, u2);
                        u1 = t1;
                        u3 = v3;
                        v2 = coeff_sub(v1, v2);
                        v1 = t2;
                        v3 = d;
                    }

                    // second value has second msb set
                    while ((v3 << 1) as $SignedT) < 0 {
                        d = u3 - v3;
                        if d < v3 {
                            // quot = 1
                            t2 = v2;
                            t1 = u2;
                            u2 = coeff_sub(u1, u2);
                            u1 = t1;
                            u3 = v3;
                            v2 = coeff_sub(v1, v2);
                            v1 = t2;
                            v3 = d;
                        } else if d < (v3 << 1) {
                            // quot = 2
                            t1 = u2;
                            u2 = coeff_sub_mul(u1, 2, u2);
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 2, v2);
                            v1 = t2;
                            v3 = d - u3;
                        } else {
                            // quot = 3
                            t1 = u2;
                            u2 = coeff_sub_mul(u1, 3, u2);
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 3, v2);
                            v1 = t2;
                            v3 = d - (u3 << 1);
                        }
                    }

                    while v3 > 0 {
                        d = u3 - v3;

                        // overflow not possible, top 2 bits of v3 not set
                        if u3 < (v3 << 2) {
                            if d < v3 {
                                // quot = 1
                                t2 = v2;
                                t1 = u2;
                                u2 = coeff_sub(u1, u2);
                                u1 = t1;
                                u3 = v3;
                                v2 = coeff_sub(v1, v2);
                                v1 = t2;
                                v3 = d;
                            } else if d < (v3 << 1) {
                                // quot = 2
                                t1 = u2;
                                u2 = coeff_sub_mul(u1, 2, u2);
                                u1 = t1;
                                u3 = v3;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 2, v2);
                                v1 = t2;
                                v3 = d - u3;
                            } else {
                                // quot = 3
                                t1 = u2;
                                u2 = coeff_sub_mul(u1, 3, u2);
                                u1 = t1;
                                u3 = v3;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 3, v2);
                                v1 = t2;
                                v3 = d - (u3 << 1);
                            }
                        } else {
                            quot = u3 / v3;
                            rem = u3 - v3 * quot;
                            t1 = u2;
                            u2 = coeff_sub_mul(u1, quot as $SignedT, u2);
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, quot as $SignedT, v2);
                            v1 = t2;
                            v3 = rem;
                        }
                    }

                    /* Remarkably, |u1| < x/2, thus comparison with 0 is valid */
                    if u1 <= 0 {
                        u1 = u1.wrapping_add_unsigned(y);
                        v1 = v1.wrapping_sub_unsigned(x);
                    }

                    (u1 as Self, v1.wrapping_neg() as Self, u3)
                }

                #[inline]
                fn gcdinv(mut x: Self, y: Self) -> (Self, Self) {
                    let mut v1: $SignedT;
                    let mut v2: $SignedT;
                    let mut t2: $SignedT;

                    let mut d: Self;
                    let mut r: Self;
                    let mut quot: Self;
                    let mut rem: Self;

                    assert!(y > x);

                    v1 = 0;
                    v2 = 1;
                    r = x;
                    x = y;

                    // y and x both have top bit set
                    if ((x & r) as $SignedT) < 0 {
                        d = x - r;
                        t2 = v2;
                        x = r;
                        v2 = coeff_sub(v1, v2);
                        v1 = t2;
                        r = d;
                    }

                    // second value has second msb set
                    while ((r << 1) as $SignedT) < 0 {
                        d = x - r;
                        if d < r {
                            // quot = 1
                            t2 = v2;
                            x = r;
                            v2 = coeff_sub(v1, v2);
                            v1 = t2;
                            r = d;
                        } else if d < (r << 1) {
                            // quot = 2
                            x = r;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 2, v2);
                            v1 = t2;
                            r = d - x;
                        } else {
                            // quot = 3
                            x = r;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 3, v2);
                            v1 = t2;
                            r = d - (x << 1);
                        }
                    }

                    while r > 0 {
                        // overflow not possible due to top 2 bits of r not being set
                        if x < (r << 2) {
                            // if quot < 4
                            d = x - r;
                            if d < r {
                                // quot = 1
                                t2 = v2;
                                x = r;
                                v2 = coeff_sub(v1, v2);
                                v1 = t2;
                                r = d;
                            } else if d < (r << 1) {
                                // quot = 2
                                x = r;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 2, v2);
                                v1 = t2;
                                r = d - x;
                            } else {
                                // quot = 3
                                x = r;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 3, v2);
                                v1 = t2;
                                r = d - (x << 1);
                            }
                        } else {
                            quot = x / r;
                            rem = x - r * quot;
                            x = r;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, quot as $SignedT, v2);
                            v1 = t2;
                            r = rem;
                        }
                    }

                    if v1 < 0 {
                        v1 = v1.wrapping_add_unsigned(y);
                    }

                    (v1 as Self, x)
                }

                #[inline]
                fn gcdinv_pow_of_2(a: Self, mask: Self) -> Option<Self> {
                    const TWO: $SelfT = 2;
                    assert!(
                        mask != 0 && (mask & mask.wrapping_add(1)) == 0,
                        "mask must be of the form 2^k - 1 for 1 <= k <= Self::BITS"
                    );
                    if a & 0b1 == 0 {
                        return None;
                    }

                    let mut x: $SelfT = INV_TABLE[((a >> 1) & 0x7F) as usize] as $SelfT;
                    for _ in 2..Self::BITS.ilog2() {
                        x = x.wrapping_mul(TWO.wrapping_sub(a.wrapping_mul(x)));
                    }
                    Some(x & mask)
                }

                #[inline]
                fn gcdinv_native(a: Self) -> Option<Self> {
                    const TWO: $SelfT = 2;
                    if a & 0b1 == 0 {
                        return None;
                    }

                    let mut x: $SelfT = INV_TABLE[((a >> 1) & 0x7F) as usize] as $SelfT;
                    for _ in 2..Self::BITS.ilog2() {
                        x = x.wrapping_mul(TWO.wrapping_sub(a.wrapping_mul(x)));
                    }
                    Some(x)
                }
            }
        };
    };
}

impl_extended_gcd!(impl Xgcd for u8; SignedType: i8);
impl_extended_gcd!(impl Xgcd for u16; SignedType: i16);
impl_extended_gcd!(impl Xgcd for u32; SignedType: i32);
impl_extended_gcd!(impl Xgcd for u64; SignedType: i64);
impl_extended_gcd!(impl Xgcd for usize; SignedType: isize);
impl_extended_gcd!(impl Xgcd for u128; SignedType: i128);
