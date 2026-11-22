use std::sync::Arc;

use cudarc::driver::{
    CudaFunction, CudaStream, CudaView, CudaViewMut, LaunchConfig, PushKernelArg,
};
use primus_lattice::LweDimension;

use super::{
    CudaError, CudaNttPlan32, THREADS, check_limit, external_product::checked_batch_len,
    launch_grid_limit,
};

const BODIES: usize = 4;

/// Expands four-body packed LWE ciphertexts into ordinary LWEs on a CUDA stream.
/// An optional body correction matches equal-block mean centering for ExactlyOne clues.
pub struct CudaPackedLweExtraction32 {
    stream: Arc<CudaStream>,
    kernel: CudaFunction,
    dimension: u32,
    modulus_mask: u32,
    center_width: u32,
    grid: u32,
    rotation_mask: u32,
    batch_capacity: usize,
}

impl CudaPackedLweExtraction32 {
    /// Binds the LWE shape to the stream and rotation period `2N` of `plan`.
    /// `modulus_mask` is `q-1` for a binary LWE modulus, including native `u32`.
    /// Pass the equal block width when ExactlyOne centering is enabled.
    ///
    /// # Errors
    /// Rejects unsupported geometry, modulus, centering arithmetic bounds or device limits,
    /// zero batch capacity, and driver failures.
    pub fn new(
        plan: &CudaNttPlan32,
        dimension: LweDimension,
        modulus_mask: u32,
        centering_block_size: Option<usize>,
        batch_capacity: usize,
    ) -> Result<Self, CudaError> {
        let dimension = dimension.get();
        let modulus = u64::from(modulus_mask) + 1;
        if dimension < BODIES || batch_capacity == 0 || modulus < 2 || !modulus.is_power_of_two() {
            return Err(CudaError::InvalidParameters(
                "invalid packed LWE geometry or modulus",
            ));
        }
        let output_stride = checked_batch_len::<u32>(BODIES, dimension + 1)?;
        checked_batch_len::<u32>(batch_capacity, output_stride as usize)?;
        let period = u64::from(2 * plan.inner.n);
        let (center_width, grid) = if let Some(width) = centering_block_size {
            let grid = modulus / period;
            if width == 0 || !dimension.is_multiple_of(width) || grid < 2 {
                return Err(CudaError::InvalidParameters(
                    "invalid packed LWE centering grid or block size",
                ));
            }
            let divisor = width as u128 * u128::from(grid);
            let numerator_bound = width as u128 * u128::from(modulus_mask)
                + dimension as u128 * u128::from(grid / 2)
                + divisor / 2;
            if numerator_bound > i64::MAX as u128 || divisor > i64::MAX as u128 {
                return Err(CudaError::InvalidParameters(
                    "packed LWE centering arithmetic exceeds i64",
                ));
            }
            (width as u32, grid as u32)
        } else {
            (0, 0)
        };
        let stream = Arc::clone(plan.stream());
        let kernel = plan
            .inner
            .module
            .load_function("primus_extract_clues_u32")?;
        let max_blocks = launch_grid_limit(&stream, &[(&kernel, 0)])?;
        check_limit("packed LWE batch size", batch_capacity, max_blocks as usize)?;
        Ok(Self {
            stream,
            kernel,
            dimension: dimension as u32,
            modulus_mask,
            center_width,
            grid,
            rotation_mask: period as u32 - 1,
            batch_capacity,
        })
    }

    /// Returns the stream used for device allocations and submission.
    #[must_use]
    pub fn stream(&self) -> &Arc<CudaStream> {
        &self.stream
    }

    /// Extracts `[mask..., body0, body1, body2, body3]` records into contiguous groups
    /// of four `[mask..., body]` LWEs. Each successive mask is a signed right rotation
    /// of the shared mask. If enabled, body centering operates on freshly extracted data.
    ///
    /// # Errors
    /// Rejects foreign streams, invalid lengths, requests over capacity, and driver errors.
    /// Argument checks precede output writes. Empty batches have empty output.
    ///
    /// # Correctness
    /// Packed coefficients must be canonical modulo the bound LWE modulus. Centering
    /// requires the equal-block ExactlyOne secret law and ordinary step-one rotation.
    pub fn extract_to(
        &self,
        input: CudaView<'_, u32>,
        mut output: CudaViewMut<'_, u32>,
    ) -> Result<(), CudaError> {
        use cudarc::driver::DeviceSlice;
        if !Arc::ptr_eq(input.stream(), &self.stream) || !Arc::ptr_eq(output.stream(), &self.stream)
        {
            return Err(CudaError::StreamMismatch);
        }
        let dimension = self.dimension as usize;
        let packed_len = dimension + BODIES;
        if !input.len().is_multiple_of(packed_len) {
            return Err(CudaError::IncompleteLweBatch {
                length: input.len(),
                lwe_length: packed_len,
            });
        }
        let batch = input.len() / packed_len;
        check_limit("packed LWE batch size", batch, self.batch_capacity)?;
        let output_len = batch * BODIES * (dimension + 1);
        if output.len() != output_len {
            return Err(CudaError::LengthMismatch {
                lhs: output_len,
                rhs: output.len(),
            });
        }
        if batch == 0 {
            return Ok(());
        }
        // SAFETY: each block owns a complete input record and its four complete
        // output LWEs. The checked views are disjoint and use the same stream.
        unsafe {
            self.stream
                .launch_builder(&self.kernel)
                .arg(&input)
                .arg(&mut output)
                .arg(&self.dimension)
                .arg(&self.modulus_mask)
                .arg(&self.center_width)
                .arg(&self.grid)
                .arg(&self.rotation_mask)
                .launch(LaunchConfig {
                    grid_dim: (batch as u32, 1, 1),
                    block_dim: (THREADS, 1, 1),
                    shared_mem_bytes: 0,
                })?;
        }
        Ok(())
    }
}
