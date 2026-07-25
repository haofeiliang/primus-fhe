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
    /// `requested_partitions` is an upper bound. The actual number can be
    /// smaller because all partitions are non-empty and have the same maximum
    /// size, matching OpenFHE's `alpha`/`beta` partitioning rule.
    pub fn new(
        q_moduli: &[M],
        p_moduli: &[M],
        requested_partitions: usize,
    ) -> Result<Self, RNSError> {
        if requested_partitions == 0 {
            return Err(RNSError::InvalidPartitionCount);
        }

        let q_base = RNSBase::new(q_moduli)?;
        let p_base = RNSBase::new(p_moduli)?;
        let qp_base = q_base.extend_with(&p_base)?;

        let partition_size = q_moduli
            .len()
            .div_ceil(requested_partitions.min(q_moduli.len()));
        let mut partitions = Vec::with_capacity(q_moduli.len().div_ceil(partition_size));

        for (partition_index, partition_moduli) in q_moduli.chunks(partition_size).enumerate() {
            let start = partition_index * partition_size;
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
                q_range: start..end,
                mod_up_converter: BaseConverter::from_owned_bases(partition_base, complement_base),
            });
        }

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
            partitions,
            p_mod_q,
            inv_p_mod_q,
            mod_down_converter,
        })
    }
}
