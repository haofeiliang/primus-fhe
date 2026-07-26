/// Immutable view of a polynomial-major `QP`-basis GLWE ciphertext.
#[derive(Clone, Copy)]
pub(in crate::glwe::key_switch) struct QpGlweRef<'a, T> {
    data: &'a [T],
    poly_length: usize,
    moduli_count: usize,
    rns_poly_len: usize,
}

impl<'a, T> QpGlweRef<'a, T> {
    /// Creates a checked view over complete `QP`-basis polynomials.
    pub(in crate::glwe::key_switch) fn new(
        data: &'a [T],
        poly_length: usize,
        moduli_count: usize,
    ) -> Self {
        let rns_poly_len = poly_length
            .checked_mul(moduli_count)
            .expect("QP polynomial length overflow");
        assert_ne!(rns_poly_len, 0);
        assert_eq!(data.len() % rns_poly_len, 0);
        Self {
            data,
            poly_length,
            moduli_count,
            rns_poly_len,
        }
    }

    /// Iterates over the same modulus limb of every GLWE polynomial.
    pub(in crate::glwe::key_switch) fn modulus_limbs(
        self,
        modulus_index: usize,
    ) -> impl ExactSizeIterator<Item = &'a [T]> {
        assert!(modulus_index < self.moduli_count);
        let limb_start = modulus_index * self.poly_length;
        let limb_end = limb_start + self.poly_length;
        self.data
            .chunks_exact(self.rns_poly_len)
            .map(move |polynomial| &polynomial[limb_start..limb_end])
    }
}

/// Mutable view of a polynomial-major `QP`-basis GLWE ciphertext.
pub(in crate::glwe::key_switch) struct QpGlweMut<'a, T> {
    data: &'a mut [T],
    poly_length: usize,
    moduli_count: usize,
    rns_poly_len: usize,
}

impl<'a, T> QpGlweMut<'a, T> {
    /// Creates a checked view over complete `QP`-basis polynomials.
    pub(in crate::glwe::key_switch) fn new(
        data: &'a mut [T],
        poly_length: usize,
        moduli_count: usize,
    ) -> Self {
        let rns_poly_len = poly_length
            .checked_mul(moduli_count)
            .expect("QP polynomial length overflow");
        assert_ne!(rns_poly_len, 0);
        assert_eq!(data.len() % rns_poly_len, 0);
        Self {
            data,
            poly_length,
            moduli_count,
            rns_poly_len,
        }
    }

    /// Iterates mutably over the same modulus limb of every GLWE polynomial.
    pub(in crate::glwe::key_switch) fn modulus_limbs_mut(
        self,
        modulus_index: usize,
    ) -> impl ExactSizeIterator<Item = &'a mut [T]> {
        assert!(modulus_index < self.moduli_count);
        let limb_start = modulus_index * self.poly_length;
        let limb_end = limb_start + self.poly_length;
        self.data
            .chunks_exact_mut(self.rns_poly_len)
            .map(move |polynomial| &mut polynomial[limb_start..limb_end])
    }
}
