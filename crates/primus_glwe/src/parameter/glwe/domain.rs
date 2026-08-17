use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::GadgetSize;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use super::GlevParameters;

/// An incompatibility between gadget parameters and a transform table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GadgetDomainError<T: FheUint> {
    /// The table and parameters use different polynomial lengths.
    #[error("polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the parameters.
        expected: usize,
        /// Polynomial length supplied by the table.
        actual: usize,
    },
    /// A single-modulus NTT table uses the wrong modulus.
    #[error("ciphertext modulus mismatch: expected {expected:?}, got {actual:?}")]
    ModulusMismatch {
        /// Modulus required by the parameters.
        expected: T,
        /// Modulus supplied by the table.
        actual: T,
    },
}

/// A checked, read-only binding of NTT gadget parameters and an NTT table.
pub struct NttGadgetDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    parameters: &'a GlevParameters<T, M>,
    table: &'a Table,
}

impl<'a, T, M, Table> NttGadgetDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Binds compatible gadget parameters and an NTT table.
    pub fn try_new(
        parameters: &'a GlevParameters<T, M>,
        table: &'a Table,
    ) -> Result<Self, GadgetDomainError<T>> {
        let expected = parameters.poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(GadgetDomainError::PolynomialLengthMismatch { expected, actual });
        }

        let expected = parameters.cipher_modulus().value();
        let actual = table.modulus();
        if actual != expected {
            return Err(GadgetDomainError::ModulusMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the bound gadget parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &'a GlevParameters<T, M> {
        self.parameters
    }

    /// Returns the bound gadget layout.
    #[must_use]
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.parameters.size()
    }

    /// Returns the bound decomposition basis.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.parameters.basis()
    }

    /// Returns the bound NTT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &'a Table {
        self.table
    }
}

#[cfg(test)]
mod tests {
    use primus_modulus::BarrettModulus;
    use primus_ntt::{NttTable, UintNttTable};

    use super::{GadgetDomainError, NttGadgetDomain};
    use crate::{GlevParameters, GlweParameters, SecretKeyDistr};

    #[test]
    fn domain_rejects_transform_shape_mismatch() {
        const Q: u32 = 132_120_577;
        let modulus = BarrettModulus::new(Q);
        let glwe = GlweParameters::new(1, 256, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let gadget = GlevParameters::with_glwe_params(&glwe, 8, Some(3));
        let wrong_length_table = UintNttTable::new(9, modulus).unwrap();
        assert!(matches!(
            NttGadgetDomain::try_new(&gadget, &wrong_length_table),
            Err(GadgetDomainError::PolynomialLengthMismatch {
                expected: 256,
                actual: 512
            })
        ));
    }
}
