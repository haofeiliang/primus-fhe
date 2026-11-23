use std::sync::Arc;

use cudarc::driver::{
    CudaFunction, CudaSlice, CudaView, CudaViewMut, DeviceRepr, PushKernelArg, ValidAsZeroBits,
};
use primus_glwe::NttGlweKeySwitchingKey;
use primus_integer::FheUint;
use primus_lattice::GlweSize;

use super::{
    CudaError, CudaNttPlan32, CudaNttPlan64, NttPlan, check_limit, checked_count,
    elementwise_config,
    external_product::{SignedDecomposition, checked_batch_len},
    launch_grid_limit,
};

pub(super) struct GlweKeySwitch<T> {
    pub(super) ntt: Arc<NttPlan<T>>,
    pub(super) input_size: GlweSize,
    pub(super) output_size: GlweSize,
    pub(super) batch_capacity: usize,
    digits: CudaSlice<T>,
    decomposition: SignedDecomposition<T>,
    decompose: CudaFunction,
    accumulate: CudaFunction,
    add_body: CudaFunction,
    barrett: Option<(u32, u64)>,
}

impl<T> GlweKeySwitch<T>
where
    T: FheUint + DeviceRepr + ValidAsZeroBits + Into<u128> + TryFrom<u128>,
{
    fn new(
        ntt: Arc<NttPlan<T>>,
        key: &NttGlweKeySwitchingKey<T>,
        batch_capacity: usize,
        [decompose, accumulate, add_body]: [&str; 3],
        barrett: Option<(u32, u64)>,
    ) -> Result<Self, CudaError> {
        let input_size = key.input_size();
        let output_size = key.output_size().glwe_size();
        if input_size.poly_length().get() != ntt.n as usize
            || output_size.poly_length() != input_size.poly_length()
            || key.output_size().level_count() != key.basis().level_count()
        {
            return Err(CudaError::InvalidParameters(
                "key switching requires matching key layouts and NTT length",
            ));
        }
        if batch_capacity == 0 {
            return Err(CudaError::InvalidParameters(
                "batch capacity must be positive",
            ));
        }
        let decomposition = SignedDecomposition::new(&ntt, key.basis())?;
        let expected_key_len = input_size
            .dimension()
            .get()
            .checked_mul(key.output_size().glev_len())
            .ok_or(CudaError::InvalidParameters(
                "key-switch key length overflow",
            ))?;
        if key.as_slice().len() != expected_key_len {
            return Err(CudaError::InvalidParameters(
                "key-switch key storage length mismatch",
            ));
        }
        checked_count::<T>(expected_key_len)?;
        checked_batch_len::<T>(batch_capacity, input_size.glwe_len())?;
        let output_count = checked_batch_len::<T>(batch_capacity, output_size.glwe_len())?;
        let mask_count = checked_batch_len::<T>(batch_capacity, input_size.mask_len())?;
        let digit_count =
            checked_batch_len::<T>(mask_count as usize, decomposition.levels as usize)?;
        check_limit(
            "grid x dimension",
            (digit_count / ntt.n) as usize,
            ntt.max_grid as usize,
        )?;
        check_limit(
            "grid x dimension",
            (output_count / ntt.n) as usize,
            ntt.max_grid as usize,
        )?;
        elementwise_config(mask_count, ntt.max_grid)?;
        elementwise_config(output_count, ntt.max_grid)?;
        let decompose = ntt.module.load_function(decompose)?;
        let accumulate = ntt.module.load_function(accumulate)?;
        let add_body = ntt.module.load_function(add_body)?;
        launch_grid_limit(
            &ntt.stream,
            &[(&decompose, 0), (&accumulate, 0), (&add_body, 0)],
        )?;
        let digits = ntt.stream.alloc_zeros(digit_count as usize)?;
        Ok(Self {
            ntt,
            input_size,
            output_size,
            batch_capacity,
            digits,
            decomposition,
            decompose,
            accumulate,
            add_body,
            barrett,
        })
    }
}

impl<T: DeviceRepr> GlweKeySwitch<T> {
    pub(super) fn key_switch_to(
        &mut self,
        key: CudaView<'_, T>,
        input: CudaView<'_, T>,
        output: CudaViewMut<'_, T>,
    ) -> Result<(), CudaError> {
        self.ntt.check_view_stream(&input)?;
        self.ntt.check_view_stream(&output)?;
        checked_count::<T>(input.len())?;
        checked_count::<T>(output.len())?;
        let input_stride = self.input_size.glwe_len();
        if !input.len().is_multiple_of(input_stride) {
            return Err(CudaError::IncompleteGlweBatch {
                length: input.len(),
                glwe_length: input_stride,
            });
        }
        let batch_size = input.len() / input_stride;
        check_limit("GLWE batch size", batch_size, self.batch_capacity)?;
        let expected = batch_size * self.output_size.glwe_len();
        if output.len() != expected {
            return Err(CudaError::LengthMismatch {
                lhs: expected,
                rhs: output.len(),
            });
        }
        self.apply_checked(key, input, output, batch_size)
    }

    // The caller checked ciphertext extents, streams and capacity. The resident
    // key has this workspace's input/output layouts, decomposition basis and NTT
    // representation, and was uploaded on the same stream.
    pub(super) fn apply_checked(
        &mut self,
        key: CudaView<'_, T>,
        input: CudaView<'_, T>,
        mut output: CudaViewMut<'_, T>,
        batch_size: usize,
    ) -> Result<(), CudaError> {
        debug_assert!(batch_size <= self.batch_capacity);
        debug_assert_eq!(input.len(), batch_size * self.input_size.glwe_len());
        debug_assert_eq!(output.len(), batch_size * self.output_size.glwe_len());
        debug_assert_eq!(
            key.len(),
            self.input_size.dimension().get()
                * self.decomposition.levels as usize
                * self.output_size.glwe_len()
        );
        if batch_size == 0 {
            return Ok(());
        }
        let ntt = &self.ntt;
        let input_dimension = self.input_size.dimension().get() as u32;
        let output_components = self.output_size.component_count() as u32;
        let mask_count = (batch_size * self.input_size.mask_len()) as u32;
        let output_count = output.len() as u32;
        let digit_count = mask_count as usize * self.decomposition.levels as usize;
        let decomposition = &self.decomposition;
        let mut digits = self.digits.slice_mut(..digit_count);
        // SAFETY: the checked batch contains input_dimension masks and one body
        // per lane. The kernel skips every body and writes all mask digit levels.
        unsafe {
            ntt.stream
                .launch_builder(&self.decompose)
                .arg(&input)
                .arg(&mut digits)
                .arg(&mask_count)
                .arg(&ntt.n)
                .arg(&input_dimension)
                .arg(&decomposition.levels)
                .arg(&decomposition.base_log)
                .arg(&decomposition.drop_bits)
                .arg(&decomposition.threshold)
                .arg(&decomposition.adjustment)
                .arg(&ntt.modulus)
                .launch(elementwise_config(mask_count, ntt.max_grid)?)?;
        }
        ntt.transform_batch(digits, digit_count as u32 / ntt.n, false)?;

        let digits = self.digits.slice(..digit_count);
        {
            let mut launch = ntt.stream.launch_builder(&self.accumulate);
            launch
                .arg(&digits)
                .arg(&key)
                .arg(&mut output)
                .arg(&output_count)
                .arg(&ntt.n)
                .arg(&input_dimension)
                .arg(&output_components)
                .arg(&decomposition.levels)
                .arg(&ntt.modulus);
            if let Some((bits, reciprocal)) = &self.barrett {
                launch.arg(bits).arg(reciprocal);
            }
            // SAFETY: one thread owns each output coefficient. Resident key rows
            // and transformed digits use the constructor-checked exact layouts.
            unsafe {
                launch.launch(elementwise_config(output_count, ntt.max_grid)?)?;
            }
        }
        ntt.transform_batch(output.slice_mut(..), output_count / ntt.n, true)?;
        let body_count = (batch_size * ntt.n as usize) as u32;
        // SAFETY: both complete batches have one body polynomial per lane.
        // Mask coefficients were fully overwritten by the accumulation and NTT.
        unsafe {
            ntt.stream
                .launch_builder(&self.add_body)
                .arg(&input)
                .arg(&mut output)
                .arg(&body_count)
                .arg(&ntt.n)
                .arg(&input_dimension)
                .arg(&output_components)
                .arg(&ntt.modulus)
                .launch(elementwise_config(body_count, ntt.max_grid)?)?;
        }
        Ok(())
    }
}

macro_rules! workspace {
    ($workspace:ident, $plan:ident, $word:ty, $decompose:literal, $accumulate:literal, $add_body:literal, $barrett:expr) => {
        /// A resident key and reusable device scratch for batched GLWE ring key switching.
        pub struct $workspace {
            pub(super) inner: GlweKeySwitch<$word>,
            pub(super) key: CudaSlice<$word>,
        }

        impl $workspace {
            /// Uploads `key` and allocates scratch for `batch_capacity` ciphertexts.
            /// The workspace retains the plan's stream, roots and kernels.
            /// Input and output GLWE dimensions may differ.
            ///
            /// # Errors
            /// Rejects a zero capacity, incompatible key/basis/layout, excessive
            /// device or ABI limits, and driver failures.
            ///
            /// # Correctness
            /// The key must use this plan's exact NTT roots, order and normalization.
            pub fn new(
                ntt: &$plan,
                key: &NttGlweKeySwitchingKey<$word>,
                batch_capacity: usize,
            ) -> Result<Self, CudaError> {
                let inner = GlweKeySwitch::new(
                    Arc::clone(&ntt.inner),
                    key,
                    batch_capacity,
                    [$decompose, $accumulate, $add_body],
                    ($barrett)(ntt),
                )?;
                let key = inner.ntt.stream.clone_htod(key.as_slice())?;
                Ok(Self { inner, key })
            }

            /// Key-switches a flat coefficient-domain GLWE batch and overwrites `output`.
            /// Each input and output lane stores its mask polynomials followed by its body.
            /// Returns canonical residues; an empty batch is accepted. Submissions reuse
            /// resident key/scratch without allocation, copying or host synchronization.
            ///
            /// # Errors
            /// Rejects incomplete input ciphertexts, mismatched output length, oversized
            /// batches, foreign allocation streams, or driver failures. Shape and stream
            /// checks precede all submissions; a driver error can leave partial output.
            ///
            /// # Correctness
            /// Input coefficients must be canonical under the plan's modulus. The operation
            /// uses the key's signed decomposition, including its configured dropped-bit
            /// approximation; it matches CPU `NttGlweKeySwitchingKey::key_switch_to` exactly.
            pub fn key_switch_to(
                &mut self,
                input: CudaView<'_, $word>,
                output: CudaViewMut<'_, $word>,
            ) -> Result<(), CudaError> {
                self.inner.key_switch_to(self.key.as_view(), input, output)
            }
        }
    };
}

workspace!(
    CudaGlweKeySwitchingWorkspace32,
    CudaNttPlan32,
    u32,
    "primus_key_switch_decompose_u32",
    "primus_key_switch_accumulate_u32",
    "primus_key_switch_add_body_u32",
    |_: &CudaNttPlan32| None
);
workspace!(
    CudaGlweKeySwitchingWorkspace64,
    CudaNttPlan64,
    u64,
    "primus_key_switch_decompose_u64",
    "primus_key_switch_accumulate_u64",
    "primus_key_switch_add_body_u64",
    |ntt: &CudaNttPlan64| Some((ntt.modulus_bits, ntt.reciprocal))
);
