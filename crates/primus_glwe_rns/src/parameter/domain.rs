use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::RnsGadgetSize;
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::{HybridRNS, RNSBase};

use super::CrtGlevParameters;

/// An incompatibility between RNS parameters and a transform table.
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
    /// A DCRT table has the wrong number of modulus limbs.
    #[error("RNS modulus count mismatch: expected {expected}, got {actual}")]
    ModuliCountMismatch {
        /// Modulus count required by the parameters.
        expected: usize,
        /// Modulus count supplied by the table.
        actual: usize,
    },
    /// A DCRT table limb uses the wrong modulus or modulus order.
    #[error("RNS modulus mismatch at index {index}: expected {expected:?}, got {actual:?}")]
    ModulusOrderMismatch {
        /// Index of the mismatching modulus.
        index: usize,
        /// Modulus required by the parameters.
        expected: T,
        /// Modulus supplied by the table.
        actual: T,
    },
}

/// A checked, read-only binding of RNS gadget parameters and a DCRT table.
pub struct DcrtGadgetDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: DcrtTable<ValueT = T>,
{
    parameters: &'a CrtGlevParameters<T, M>,
    table: &'a Table,
}

impl<'a, T, M, Table> DcrtGadgetDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: DcrtTable<ValueT = T>,
{
    /// Binds compatible RNS gadget parameters and a DCRT table.
    pub fn try_new(
        parameters: &'a CrtGlevParameters<T, M>,
        table: &'a Table,
    ) -> Result<Self, GadgetDomainError<T>> {
        let expected = parameters.poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(GadgetDomainError::PolynomialLengthMismatch { expected, actual });
        }

        let expected = parameters.cipher_moduli_count();
        let actual = table.moduli_count();
        if actual != expected {
            return Err(GadgetDomainError::ModuliCountMismatch { expected, actual });
        }

        for (index, (expected, ntt_table)) in parameters
            .cipher_moduli_value()
            .iter()
            .copied()
            .zip(table.ntt_tables())
            .enumerate()
        {
            let actual = ntt_table.modulus();
            if actual != expected {
                return Err(GadgetDomainError::ModulusOrderMismatch {
                    index,
                    expected,
                    actual,
                });
            }
        }

        Ok(Self { parameters, table })
    }

    /// Returns the bound RNS gadget parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &'a CrtGlevParameters<T, M> {
        self.parameters
    }

    /// Returns the bound RNS gadget layout.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGadgetSize {
        self.parameters.size()
    }

    /// Returns the bound decomposition basis.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<T> {
        self.parameters.basis()
    }

    /// Returns the bound DCRT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &'a Table {
        self.table
    }

    /// Returns the RNS basis used by the bound parameters.
    #[must_use]
    #[inline]
    pub fn rns_base(&self) -> &'a RNSBase<T, M> {
        self.parameters.base_q()
    }
}

/// A checked binding of hybrid-RNS bases and converters to their DCRT table.
pub struct HybridRnsKeySwitchDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: DcrtTable<ValueT = T>,
{
    hybrid_rns: &'a HybridRNS<T, M>,
    table: &'a Table,
}

impl<'a, T, M, Table> HybridRnsKeySwitchDomain<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: DcrtTable<ValueT = T>,
{
    /// Binds a complete ordered `Q/P` basis to a matching DCRT table.
    pub fn try_new(
        hybrid_rns: &'a HybridRNS<T, M>,
        table: &'a Table,
    ) -> Result<Self, GadgetDomainError<T>> {
        let expected = hybrid_rns.qp_moduli_count();
        let actual = table.moduli_count();
        if actual != expected {
            return Err(GadgetDomainError::ModuliCountMismatch { expected, actual });
        }
        for (index, (modulus, ntt_table)) in hybrid_rns
            .qp_base()
            .moduli()
            .iter()
            .zip(table.ntt_tables())
            .enumerate()
        {
            let expected = modulus.value();
            let actual = ntt_table.modulus();
            if actual != expected {
                return Err(GadgetDomainError::ModulusOrderMismatch {
                    index,
                    expected,
                    actual,
                });
            }
            let expected = table.poly_length();
            let actual = ntt_table.poly_length();
            if actual != expected {
                return Err(GadgetDomainError::PolynomialLengthMismatch { expected, actual });
            }
        }
        Ok(Self { hybrid_rns, table })
    }

    /// Returns the bound hybrid-RNS bases and converters.
    #[must_use]
    #[inline]
    pub fn hybrid_rns(&self) -> &'a HybridRNS<T, M> {
        self.hybrid_rns
    }

    /// Returns the bound DCRT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &'a Table {
        self.table
    }

    /// Returns the ordered `Q` basis.
    #[must_use]
    #[inline]
    pub fn q_base(&self) -> &'a RNSBase<T, M> {
        self.hybrid_rns.q_base()
    }

    /// Returns the ordered auxiliary `P` basis.
    #[must_use]
    #[inline]
    pub fn p_base(&self) -> &'a RNSBase<T, M> {
        self.hybrid_rns.p_base()
    }

    /// Returns the complete ordered `Q || P` basis.
    #[must_use]
    #[inline]
    pub fn qp_base(&self) -> &'a RNSBase<T, M> {
        self.hybrid_rns.qp_base()
    }
}

#[cfg(test)]
mod tests {
    use primus_modulus::BarrettModulus;
    use primus_ntt::{DcrtTable, U64DcrtTable};

    use super::{DcrtGadgetDomain, GadgetDomainError};
    use crate::{CrtGlevParameters, CrtGlweParameters, SecretKeyDistr};

    #[test]
    fn domain_rejects_modulus_order_mismatch() {
        let moduli_values = [1_125_899_906_826_241u64, 1_125_899_906_629_633];
        let moduli = moduli_values.map(BarrettModulus::new);
        let crt_glwe = CrtGlweParameters::new(
            1,
            256,
            BarrettModulus::new(12_289),
            BarrettModulus::new(2_199_023_190_017),
            &moduli,
            SecretKeyDistr::Ternary,
            3.2,
        );
        let crt_gadget = CrtGlevParameters::with_glwe_params(&crt_glwe, 20, None);
        let reversed = [moduli[1], moduli[0]];
        let wrong_order_table = U64DcrtTable::new(8, &reversed).unwrap();
        assert!(matches!(
            DcrtGadgetDomain::try_new(&crt_gadget, &wrong_order_table),
            Err(GadgetDomainError::ModulusOrderMismatch { index: 0, .. })
        ));
    }
}
