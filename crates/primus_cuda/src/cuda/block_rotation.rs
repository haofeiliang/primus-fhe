use cudarc::driver::{
    CudaFunction, CudaSlice, CudaView, CudaViewMut, DeviceRepr, PushKernelArg, ValidAsZeroBits,
};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_tfhe_glwe::{BlockGlweBootstrappingKey, BlockOccupancy};

use super::{
    CudaError, CudaExternalProductWorkspace32, CudaExternalProductWorkspace64, CudaNttPlan32,
    CudaNttPlan64, check_limit, checked_count, elementwise_config,
    external_product::{ExternalProduct, checked_batch_len},
    launch_grid_limit,
};

struct BlockRotation<'a, T> {
    external: ExternalProduct<'a, T>,
    key: CudaSlice<T>,
    aggregate: CudaSlice<T>,
    aggregate_block: CudaFunction,
    blocks: usize,
    key_block_len: usize,
    gadget_len: u32,
    block_width: u32,
    has_dummy: u32,
}

impl<'a, T> BlockRotation<'a, T>
where
    T: FheUint + DeviceRepr + ValidAsZeroBits,
{
    fn new(
        external: ExternalProduct<'a, T>,
        key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
        aggregate_name: &str,
    ) -> Result<Self, CudaError> {
        let ntt = external.ntt;
        let blocks = key.blocks().len();
        let key_block_len = key.as_slice().len() / blocks;
        checked_count::<T>(key.as_slice().len())?;
        let capacity = (external.batch_capacity * external.size.ggsw_len()) as u32;
        checked_batch_len::<u32>(external.batch_capacity, key.block_size())?;
        elementwise_config(capacity, ntt.max_grid)?;
        check_limit(
            "grid x dimension",
            (capacity / ntt.n) as usize,
            ntt.max_grid as usize,
        )?;
        let aggregate_block = ntt.module.load_function(aggregate_name)?;
        launch_grid_limit(&ntt.stream, &[(&aggregate_block, 0)])?;
        let aggregate = ntt.stream.alloc_zeros(capacity as usize)?;
        let has_dummy = u32::from(key.occupancy() == BlockOccupancy::AtMostOne);
        Ok(Self {
            external,
            key: ntt.stream.clone_htod(key.as_slice())?,
            aggregate,
            aggregate_block,
            blocks,
            key_block_len,
            gadget_len: key.size().ggsw_len() as u32,
            block_width: key.block_size() as u32,
            has_dummy,
        })
    }
}

impl<T: DeviceRepr> BlockRotation<'_, T> {
    fn apply_block_to(
        &mut self,
        block_index: usize,
        exponents: CudaView<'_, u32>,
        input: CudaView<'_, T>,
        output: CudaViewMut<'_, T>,
    ) -> Result<(), CudaError> {
        check_limit("Block index", block_index, self.blocks - 1)?;
        let count = self.external.check_batch(&input, &output)?;
        let ntt = self.external.ntt;
        ntt.check_view_stream(&exponents)?;
        let lanes = count as usize / self.external.size.glwe_len();
        let exponent_count = lanes * self.block_width as usize;
        if exponents.len() != exponent_count {
            return Err(CudaError::LengthMismatch {
                lhs: exponent_count,
                rhs: exponents.len(),
            });
        }
        if count == 0 {
            return Ok(());
        }
        self.apply_block_checked(block_index, exponents, input, output, count)
    }

    fn apply_block_checked(
        &mut self,
        block_index: usize,
        exponents: CudaView<'_, u32>,
        input: CudaView<'_, T>,
        output: CudaViewMut<'_, T>,
        count: u32,
    ) -> Result<(), CudaError> {
        let ntt = self.external.ntt;
        let start = block_index * self.key_block_len;
        let block = self.key.slice(start..start + self.key_block_len);
        let lanes = count as usize / self.external.size.glwe_len();
        let aggregate_count = lanes as u32 * self.gadget_len;
        let config = elementwise_config(aggregate_count, ntt.max_grid)?;
        let mut aggregate = self.aggregate.slice_mut(..aggregate_count as usize);
        // SAFETY: the uploaded block contains all complete selectors and the
        // optional dummy, and the exponents match the validated batch shape.
        // Input and output allocations are disjoint and ordered on one stream.
        unsafe {
            ntt.stream
                .launch_builder(&self.aggregate_block)
                .arg(&block)
                .arg(&exponents)
                .arg(&mut aggregate)
                .arg(&aggregate_count)
                .arg(&ntt.n)
                .arg(&self.gadget_len)
                .arg(&self.block_width)
                .arg(&self.has_dummy)
                .arg(&ntt.modulus)
                .launch(config)?;
        }
        ntt.transform_batch(aggregate, aggregate_count / ntt.n, false)?;
        self.external.apply_checked(
            self.aggregate.slice(..aggregate_count as usize),
            input,
            output,
            count,
        )
    }
}

struct BlindRotation<'a, T> {
    update: BlockRotation<'a, T>,
    exponents: CudaSlice<u32>,
    accumulator: CudaSlice<T>,
    quantize: CudaFunction,
    initialize: CudaFunction,
    lwe_dimension: u32,
    input_bits: Option<u32>,
    rotation_bits: u32,
}

impl<'a, T> BlindRotation<'a, T>
where
    T: FheUint + DeviceRepr + ValidAsZeroBits,
{
    fn new(
        external: ExternalProduct<'a, T>,
        key: &BlockGlweBootstrappingKey<T, BarrettModulus<T>>,
        [aggregate_name, quantize_name, initialize_name]: [&str; 3],
    ) -> Result<Self, CudaError> {
        let ntt = external.ntt;
        let dimension = key.input_dimension().get();
        let lwe_length = dimension + 1;
        let lwe_count = checked_batch_len::<T>(external.batch_capacity, lwe_length)?;
        let exponent_count = checked_batch_len::<u32>(external.batch_capacity, lwe_length)?;
        elementwise_config(lwe_count, ntt.max_grid)?;
        let accumulator_count = external.batch_capacity * external.size.glwe_len();
        let input_bits = match key.input_modulus_value() {
            None => Some(T::BITS),
            Some(q) if q.is_power_of_two() => Some(q.trailing_zeros()),
            Some(_) => None,
        };
        let quantize = ntt.module.load_function(quantize_name)?;
        let initialize = ntt.module.load_function(initialize_name)?;
        launch_grid_limit(&ntt.stream, &[(&quantize, 0), (&initialize, 0)])?;
        let update = BlockRotation::new(external, key, aggregate_name)?;
        Ok(Self {
            update,
            exponents: ntt.stream.alloc_zeros(exponent_count as usize)?,
            accumulator: ntt.stream.alloc_zeros(accumulator_count)?,
            quantize,
            initialize,
            lwe_dimension: dimension as u32,
            input_bits,
            rotation_bits: (2 * ntt.n).ilog2(),
        })
    }
}

impl<T: DeviceRepr> BlindRotation<'_, T> {
    fn blind_rotate_lookup_table_to(
        &mut self,
        input: CudaView<'_, T>,
        lut: CudaView<'_, T>,
        mut output: CudaViewMut<'_, T>,
    ) -> Result<(), CudaError> {
        let input_bits = self.input_bits.ok_or(CudaError::InvalidParameters(
            "blind rotation requires a power-of-two LWE modulus",
        ))?;
        let ntt = self.update.external.ntt;
        ntt.check_view_stream(&input)?;
        ntt.check_operand_length(ntt.n as usize, &lut)?;
        ntt.check_view_stream(&output)?;
        let lwe_length = self.lwe_dimension as usize + 1;
        if !input.len().is_multiple_of(lwe_length) {
            return Err(CudaError::IncompleteLweBatch {
                length: input.len(),
                lwe_length,
            });
        }
        let lanes = input.len() / lwe_length;
        check_limit("LWE batch size", lanes, self.update.external.batch_capacity)?;
        let glwe_len = self.update.external.size.glwe_len();
        let output_len = lanes * glwe_len;
        if output.len() != output_len {
            return Err(CudaError::LengthMismatch {
                lhs: output_len,
                rhs: output.len(),
            });
        }
        if lanes == 0 {
            return Ok(());
        }
        let lanes = lanes as u32;
        let input_count = input.len() as u32;
        let count = output_len as u32;
        let glwe_len = glwe_len as u32;
        let quantize_config = elementwise_config(input_count, ntt.max_grid)?;
        let initialize_config = elementwise_config(count, ntt.max_grid)?;
        let mut exponents = self.exponents.slice_mut(..input_count as usize);
        // SAFETY: both slices hold all lanes, including one body per input.
        // The bound modulus is 2^input_bits. Rotation bits come from 2N.
        unsafe {
            ntt.stream
                .launch_builder(&self.quantize)
                .arg(&input)
                .arg(&mut exponents)
                .arg(&input_count)
                .arg(&self.lwe_dimension)
                .arg(&self.update.block_width)
                .arg(&lanes)
                .arg(&input_bits)
                .arg(&self.rotation_bits)
                .launch(quantize_config)?;
        }
        let body_start = (lanes * self.lwe_dimension) as usize;
        let bodies = self.exponents.slice(body_start..input_count as usize);
        let mut scratch = self.accumulator.slice_mut(..output_len);
        // Choose the initial destination so the final block writes directly to output.
        let mut current_is_output = self.update.blocks.is_multiple_of(2);
        let mut initial = if current_is_output {
            output.slice_mut(..)
        } else {
            scratch.slice_mut(..)
        };
        // SAFETY: there is one negative body exponent per complete output GLWE,
        // a shared N-coefficient LUT and disjoint storage on the plan stream.
        unsafe {
            ntt.stream
                .launch_builder(&self.initialize)
                .arg(&lut)
                .arg(&bodies)
                .arg(&mut initial)
                .arg(&count)
                .arg(&ntt.n)
                .arg(&glwe_len)
                .arg(&ntt.modulus)
                .launch(initialize_config)?;
        }
        let block_stride = (lanes * self.update.block_width) as usize;
        for block_index in 0..self.update.blocks {
            let start = block_index * block_stride;
            let exponents = self.exponents.slice(start..start + block_stride);
            let (input, output) = if current_is_output {
                (output.as_view(), scratch.slice_mut(..))
            } else {
                (scratch.as_view(), output.slice_mut(..))
            };
            self.update
                .apply_block_checked(block_index, exponents, input, output, count)?;
            current_is_output = !current_is_output;
        }
        debug_assert!(current_is_output);
        Ok(())
    }
}

macro_rules! workspace {
    ($workspace:ident, $ext:ident, $plan:ident, $word:ty, $aggregate:literal, $quantize:literal,
     $initialize:literal) => {
        /// Uploaded Block GLWE bootstrapping key and reusable scratch for batched block updates.
        pub struct $workspace<'a> {
            inner: BlindRotation<'a, $word>,
        }

        impl<'a> $workspace<'a> {
            /// Uploads a coefficient-domain Block key and prepares scratch on `ntt.stream()`.
            ///
            /// # Errors
            /// Rejects zero capacity, dimensions or basis incompatible with the plan,
            /// excessive storage/launch requirements, and driver failures.
            pub fn new(
                ntt: &'a $plan,
                key: &BlockGlweBootstrappingKey<$word, BarrettModulus<$word>>,
                batch_capacity: usize,
            ) -> Result<Self, CudaError> {
                let external = $ext::new(ntt, key.size(), key.basis(), batch_capacity)?;
                Ok(Self {
                    inner: BlindRotation::new(
                        external.inner,
                        key,
                        [$aggregate, $quantize, $initialize],
                    )?,
                })
            }

            /// Evaluates one shared ordinary LUT for each input LWE and writes coefficient-domain GLWEs.
            /// The input is a flat batch of `[mask, body]` ciphertexts in key order. The LUT has
            /// exactly `N` canonical coefficients. Empty batches are accepted with a valid LUT.
            /// The workspace applies step-one rotation quantization and retains all scratch on the GPU.
            ///
            /// # Errors
            /// Rejects a foreign allocation stream, a non-power-of-two LWE modulus, illegal batch or
            /// LUT lengths, or driver failures. Argument checks precede output writes. A driver failure
            /// can leave partially written outputs.
            ///
            /// # Correctness
            /// Input coefficients must be canonical under the key's LWE modulus and use its
            /// block-binary input secret. The LUT must use the ring modulus and ordinary rotation
            /// spacing, with a suitable encoding and noise margin.
            pub fn blind_rotate_lookup_table_to(
                &mut self,
                input: CudaView<'_, $word>,
                lut: CudaView<'_, $word>,
                output: CudaViewMut<'_, $word>,
            ) -> Result<(), CudaError> {
                self.inner.blind_rotate_lookup_table_to(input, lut, output)
            }

            /// Replaces each lane's accumulator with the external product by one Block aggregate.
            /// Every lane uses the same key block and its own `block_width` exponents, interpreted
            /// modulo `2N`. AtMostOne includes the stored dummy; ExactlyOne aggregates selectors.
            /// Empty batches are accepted with an in-range block index.
            ///
            /// # Errors
            /// Rejects invalid block indices, incomplete or incompatible batches, foreign streams,
            /// and driver failures.
            ///
            /// # Correctness
            /// Pass canonical coefficient-domain GLWE inputs in mask-then-body order and equally
            /// sized outputs on the plan's stream. Inputs must use the key's accumulator secret.
            /// The caller initializes the accumulator and supplies quantized exponents in key order.
            pub fn apply_block_to(
                &mut self,
                block_index: usize,
                exponents: CudaView<'_, u32>,
                input: CudaView<'_, $word>,
                output: CudaViewMut<'_, $word>,
            ) -> Result<(), CudaError> {
                self.inner
                    .update
                    .apply_block_to(block_index, exponents, input, output)
            }
        }
    };
}

workspace!(
    CudaBlockBlindRotationWorkspace32,
    CudaExternalProductWorkspace32,
    CudaNttPlan32,
    u32,
    "primus_aggregate_block_u32",
    "primus_block_quantize_u32",
    "primus_block_initialize_u32"
);
workspace!(
    CudaBlockBlindRotationWorkspace64,
    CudaExternalProductWorkspace64,
    CudaNttPlan64,
    u64,
    "primus_aggregate_block_u64",
    "primus_block_quantize_u64",
    "primus_block_initialize_u64"
);
