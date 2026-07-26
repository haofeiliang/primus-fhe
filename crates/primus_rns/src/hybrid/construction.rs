use primus_integer::{BigUint, FheUint};
use primus_reduce::FieldContext;

use crate::{BaseConverter, RNSBase, RNSError};

use super::{HybridRNS, HybridRNSPartition};

impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates hybrid RNS precomputations for bases `Q` and `P`.
    ///
    /// `decomposition_count` (`dnum`) is the requested number of digits and an
    /// upper bound on the actual number of non-empty partitions. Each
    /// partition contains at most `partition_moduli_count` (`alpha`) moduli;
    /// the actual `partition_count` (`beta`) can be smaller than `dnum`.
    pub fn new(
        q_moduli: &[M],
        p_moduli: &[M],
        decomposition_count: usize,
    ) -> Result<Self, RNSError> {
        if decomposition_count == 0 {
            return Err(RNSError::InvalidDecompositionCount);
        }

        let q_base = RNSBase::new(q_moduli)?;
        let p_base = RNSBase::new(p_moduli)?;
        let qp_base = q_base.extend_with(&p_base)?;

        let partition_moduli_count = q_moduli
            .len()
            .div_ceil(decomposition_count.min(q_moduli.len()));
        let partition_count = q_moduli.len().div_ceil(partition_moduli_count);
        let mut partitions = Vec::with_capacity(partition_count);

        let mut start = 0;
        for partition_moduli in q_moduli.chunks(partition_moduli_count) {
            let end = start + partition_moduli.len();
            let partition_base = RNSBase::from_owned_moduli(partition_moduli.to_vec())?;
            let complement_moduli = q_moduli[..start]
                .iter()
                .chain(&q_moduli[end..])
                .chain(p_moduli)
                .copied()
                .collect();
            let complement_base = RNSBase::from_owned_moduli(complement_moduli)?;

            partitions.push(HybridRNSPartition {
                q_range: (start..end).into(),
                q_moduli_count: q_moduli.len(),
                mod_up_converter: BaseConverter::from_owned_bases(partition_base, complement_base),
            });
            start = end;
        }

        debug_assert_eq!(partitions.len(), partition_count);

        let BigUint(p) = p_base.moduli_product();
        let mut p_mod_q = Vec::with_capacity(q_moduli.len());
        let mut inv_p_mod_q = Vec::with_capacity(q_moduli.len());
        for qi in q_moduli {
            let p_mod_qi = qi.reduce(p);
            p_mod_q.push(p_mod_qi);
            inv_p_mod_q.push(qi.reduce_inv(p_mod_qi));
        }

        let mod_down_converter = BaseConverter::new(&p_base, &q_base);

        Ok(Self {
            q_base,
            p_base,
            qp_base,
            decomposition_count,
            partition_moduli_count,
            partitions,
            p_mod_q,
            inv_p_mod_q,
            mod_down_converter,
        })
    }
}
