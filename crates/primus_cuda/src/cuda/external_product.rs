use std::sync::Arc;

use cudarc::driver::{
    CudaFunction, CudaSlice, CudaView, CudaViewMut, DeviceRepr, PushKernelArg, ValidAsZeroBits,
};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::GadgetSize;

use super::{
    CudaError, CudaNttPlan32, CudaNttPlan64, NttPlan, check_limit, checked_count,
    elementwise_config, launch_grid_limit,
};

pub(super) struct ExternalProduct<T> {
    pub(super) ntt: Arc<NttPlan<T>>,
    pub(super) size: GadgetSize,
    pub(super) batch_capacity: usize,
    digits: CudaSlice<T>,
    decompose: CudaFunction,
    accumulate: CudaFunction,
    components: u32,
    decomposition: SignedDecomposition<T>,
    modulus_bits: Option<u32>,
    reciprocal: u64,
}

pub(super) struct SignedDecomposition<T> {
    pub(super) levels: u32,
    pub(super) base_log: u32,
    pub(super) drop_bits: u32,
    pub(super) threshold: T,
    pub(super) adjustment: T,
}

impl<T: FheUint + Into<u128> + TryFrom<u128>> SignedDecomposition<T> {
    pub(super) fn new(ntt: &NttPlan<T>, basis: &ApproxSignedBasis<T>) -> Result<Self, CudaError> {
        if basis.modulus() != Some(ntt.modulus) || basis.modulus_is_power_of_2() {
            return Err(CudaError::InvalidParameters(
                "signed decomposition requires the plan's explicit odd modulus",
            ));
        }
        let drop_bits = basis.drop_bits();
        let half_base = basis.basis_value().into() >> 1;
        let max_positive: u128 = basis
            .scalar_iter()
            .map(|weight| (half_base - 1) * weight.into())
            .sum();
        // Match ApproxSignedBasis::wrap_threshold: with no dropped bits the
        // split lies one above the largest positive representable integer.
        let threshold = T::try_from(max_positive + (1u128 << drop_bits.saturating_sub(1)))
            .map_err(|_| CudaError::InvalidParameters("decomposition threshold overflow"))?;
        let q = ntt.modulus.into();
        let adjustment = T::try_from((1u128 << (q.ilog2() + 1)) - q)
            .map_err(|_| CudaError::InvalidParameters("decomposition adjustment overflow"))?;
        Ok(Self {
            levels: basis.level_count().get() as u32,
            base_log: basis.log_basis().get(),
            drop_bits,
            threshold,
            adjustment,
        })
    }
}

pub(super) fn checked_batch_len<T>(count: usize, stride: usize) -> Result<u32, CudaError> {
    let length = count
        .checked_mul(stride)
        .ok_or(CudaError::InvalidParameters(
            "batch storage length overflow",
        ))?;
    checked_count::<T>(length)
}

impl<T> ExternalProduct<T>
where
    T: FheUint + DeviceRepr + ValidAsZeroBits + Into<u128> + TryFrom<u128>,
{
    fn new(
        ntt: &Arc<NttPlan<T>>,
        size: GadgetSize,
        basis: &ApproxSignedBasis<T>,
        batch_capacity: usize,
        [decompose, accumulate]: [&str; 2],
        (modulus_bits, reciprocal): (Option<u32>, u64),
    ) -> Result<Self, CudaError> {
        if size.glwe_size().poly_length().get() != ntt.n as usize
            || size.level_count() != basis.level_count()
        {
            return Err(CudaError::InvalidParameters(
                "external product requires a matching GLWE size and explicit odd-modulus basis",
            ));
        }
        let decomposition = SignedDecomposition::new(ntt, basis)?;
        if batch_capacity == 0 {
            return Err(CudaError::InvalidParameters(
                "batch capacity must be positive",
            ));
        }
        // The gadget contains every digit polynomial once per output component.
        // Bounding its length also bounds the GLWE and digit batches.
        checked_batch_len::<T>(batch_capacity, size.ggsw_len())?;
        let components = size.glwe_size().component_count() as u32;
        let levels = basis.level_count().get() as u32;
        let digit_len = batch_capacity * size.glwe_len() * levels as usize;
        check_limit(
            "grid x dimension",
            digit_len / ntt.n as usize,
            ntt.max_grid as usize,
        )?;
        elementwise_config((batch_capacity * size.glwe_len()) as u32, ntt.max_grid)?;

        let decompose = ntt.module.load_function(decompose)?;
        let accumulate = ntt.module.load_function(accumulate)?;
        launch_grid_limit(&ntt.stream, &[(&decompose, 0), (&accumulate, 0)])?;
        let digits = ntt.stream.alloc_zeros(digit_len)?;
        Ok(Self {
            ntt: Arc::clone(ntt),
            size,
            batch_capacity,
            digits,
            decompose,
            accumulate,
            components,
            decomposition,
            modulus_bits,
            reciprocal,
        })
    }
}

impl<T: DeviceRepr> ExternalProduct<T> {
    pub(super) fn check_batch(
        &self,
        input: &CudaView<'_, T>,
        output: &CudaViewMut<'_, T>,
    ) -> Result<u32, CudaError> {
        let count = self.ntt.matching_count(output, input)?;
        let glwe_length = self.size.glwe_len();
        if !input.len().is_multiple_of(glwe_length) {
            return Err(CudaError::IncompleteGlweBatch {
                length: input.len(),
                glwe_length,
            });
        }
        check_limit(
            "GLWE batch size",
            input.len() / glwe_length,
            self.batch_capacity,
        )?;
        Ok(count)
    }

    pub(super) fn external_product_to(
        &mut self,
        gadget_ntt: CudaView<'_, T>,
        input: CudaView<'_, T>,
        output: CudaViewMut<'_, T>,
    ) -> Result<(), CudaError> {
        let count = self.check_batch(&input, &output)?;
        let batch_size = input.len() / self.size.glwe_len();
        self.ntt
            .check_operand_length(batch_size * self.size.ggsw_len(), &gadget_ntt)?;
        self.apply_checked(gadget_ntt, input, output, count)
    }

    // The caller has validated all operand extents, including workspace capacity.
    pub(super) fn apply_checked(
        &mut self,
        gadget_ntt: CudaView<'_, T>,
        input: CudaView<'_, T>,
        mut output: CudaViewMut<'_, T>,
        count: u32,
    ) -> Result<(), CudaError> {
        if count == 0 {
            return Ok(());
        }
        let ntt = &self.ntt;
        let config = elementwise_config(count, ntt.max_grid)?;
        let decomposition = &self.decomposition;
        let digit_len = count as usize * decomposition.levels as usize;
        let mut digits = self.digits.slice_mut(..digit_len);
        // SAFETY: the entry point writes one digit polynomial per input
        // polynomial and level. Both views are distinct and on ntt's stream.
        unsafe {
            ntt.stream
                .launch_builder(&self.decompose)
                .arg(&input)
                .arg(&mut digits)
                .arg(&count)
                .arg(&ntt.n)
                .arg(&decomposition.levels)
                .arg(&decomposition.base_log)
                .arg(&decomposition.drop_bits)
                .arg(&decomposition.threshold)
                .arg(&decomposition.adjustment)
                .arg(&ntt.modulus)
                .launch(config)?;
        }
        ntt.transform_batch(digits, count / ntt.n * decomposition.levels, false)?;

        let digits = self.digits.slice(..digit_len);
        {
            let mut launch = ntt.stream.launch_builder(&self.accumulate);
            launch
                .arg(&digits)
                .arg(&gadget_ntt)
                .arg(&mut output)
                .arg(&count)
                .arg(&ntt.n)
                .arg(&self.components)
                .arg(&decomposition.levels)
                .arg(&ntt.modulus);
            if let Some(bits) = &self.modulus_bits {
                launch.arg(bits);
            }
            launch.arg(&self.reciprocal);
            // SAFETY: the typed entry point reads each lane's gadget and transformed
            // digits, and writes exactly count coefficients on the same stream.
            unsafe { launch.launch(config)? };
        }
        ntt.transform_batch(output, count / ntt.n, true)
    }
}

macro_rules! workspace {
    ($workspace:ident, $plan:ident, $word:ty, $decompose:literal, $reduce:literal, $barrett:expr) => {
        /// Reusable device scratch for batched GLWE external products of this word width.
        pub struct $workspace {
            pub(super) inner: ExternalProduct<$word>,
        }

        impl $workspace {
            /// Allocates scratch for up to `batch_capacity` GLWE ciphertexts on `ntt.stream()`.
            ///
            /// # Errors
            /// Rejects incompatible basis, dimensions or device limits, zero capacity,
            /// and driver failures.
            pub fn new(
                ntt: &$plan,
                size: GadgetSize,
                basis: &ApproxSignedBasis<$word>,
                batch_capacity: usize,
            ) -> Result<Self, CudaError> {
                Ok(Self {
                    inner: ExternalProduct::new(
                        &ntt.inner,
                        size,
                        basis,
                        batch_capacity,
                        [$decompose, $reduce],
                        ($barrett)(ntt),
                    )?,
                })
            }

            /// Submits one external product per lane and overwrites coefficient-domain output.
            /// Each lane contains one NTT GGSW and one coefficient-domain GLWE. Empty batches
            /// are accepted. Device scratch is reused on the plan's stream.
            ///
            /// # Errors
            /// Rejects incomplete, unequal or oversized batches, foreign streams, and
            /// driver failures.
            ///
            /// # Correctness
            /// All coefficients are canonical. Each GGSW uses the plan's NTT roots and
            /// layout `[input component][level][output component][coefficient]`, with
            /// the lowest retained level first. Each GLWE uses mask-then-body order.
            /// Key, basis and modulus must be compatible.
            pub fn external_product_to(
                &mut self,
                gadget_ntt: CudaView<'_, $word>,
                input: CudaView<'_, $word>,
                output: CudaViewMut<'_, $word>,
            ) -> Result<(), CudaError> {
                self.inner.external_product_to(gadget_ntt, input, output)
            }
        }
    };
}

workspace!(
    CudaExternalProductWorkspace32,
    CudaNttPlan32,
    u32,
    "primus_decompose_u32",
    "primus_external_product_u32",
    |ntt: &CudaNttPlan32| {
        // The plan's checked q > 1 makes floor(2^64 / q) fit in u64.
        (None, ((1u128 << 64) / u128::from(ntt.modulus())) as u64)
    }
);
workspace!(
    CudaExternalProductWorkspace64,
    CudaNttPlan64,
    u64,
    "primus_decompose_u64",
    "primus_external_product_u64",
    |ntt: &CudaNttPlan64| (Some(ntt.modulus_bits), ntt.reciprocal)
);
