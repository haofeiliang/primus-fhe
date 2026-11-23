use std::sync::Arc;

use cudarc::driver::{
    CudaFunction, CudaView, CudaViewMut, DeviceRepr, LaunchConfig, PushKernelArg,
};
use primus_lattice::{GlweSize, LweDimension};

use super::{
    CudaError, CudaNttPlan32, NttPlan, check_limit, elementwise_config,
    external_product::checked_batch_len, launch_grid_limit,
};

/// CUDA arithmetic used between OMR's two blind rotations.
/// Binds four-body sums, rank-one compact extraction and switching to `q=4096`.
pub struct CudaOmrBridge32 {
    ntt: Arc<NttPlan<u32>>,
    sum: CudaFunction,
    extract: CudaFunction,
    switch: CudaFunction,
    glwe_len: u32,
    lwe_len: u32,
    capacity: usize,
    reciprocal: u64,
}

impl CudaOmrBridge32 {
    /// Binds rank-one BR1 output and the active prefix of the second LWE secret.
    /// All device views use the plan's stream. Capacity counts complete clues.
    ///
    /// # Errors
    /// Rejects incompatible rank, degree, prefix size, capacity or device limits.
    pub fn new(
        plan: &CudaNttPlan32,
        glwe_size: GlweSize,
        lwe_dimension: LweDimension,
        capacity: usize,
    ) -> Result<Self, CudaError> {
        if glwe_size.dimension().get() != 1
            || glwe_size.poly_length().get() != plan.poly_length()
            || lwe_dimension.get() > plan.poly_length()
            || capacity == 0
        {
            return Err(CudaError::InvalidParameters(
                "incompatible OMR bridge geometry",
            ));
        }
        let glwe_len = glwe_size.glwe_len();
        let lwe_len = lwe_dimension.get() + 1;
        checked_batch_len::<u32>(capacity, 4 * glwe_len)?;
        checked_batch_len::<u64>(capacity, lwe_len)?;
        let ntt = Arc::clone(&plan.inner);
        let sum = ntt.module.load_function("primus_omr_sum_four_u32")?;
        let extract = ntt.module.load_function("primus_omr_extract_u32")?;
        let switch = ntt.module.load_function("primus_omr_switch_u32_to_u64")?;
        let max_grid = launch_grid_limit(&ntt.stream, &[(&sum, 0), (&extract, 0), (&switch, 0)])?;
        elementwise_config((capacity * glwe_len.max(lwe_len)) as u32, max_grid)?;
        let reciprocal = ((1u128 << 64) / u128::from(ntt.modulus)) as u64;
        Ok(Self {
            ntt,
            sum,
            extract,
            switch,
            glwe_len: glwe_len as u32,
            lwe_len: lwe_len as u32,
            capacity,
            reciprocal,
        })
    }

    fn check_batch<T: DeviceRepr>(
        &self,
        input: &CudaView<'_, u32>,
        output: &CudaViewMut<'_, T>,
        input_stride: u32,
        output_stride: u32,
    ) -> Result<Option<(u32, LaunchConfig)>, CudaError> {
        self.ntt.check_view_stream(input)?;
        self.ntt.check_view_stream(output)?;
        if !input.len().is_multiple_of(input_stride as usize) {
            return Err(CudaError::InvalidParameters(
                "incomplete OMR bridge input batch",
            ));
        }
        let batch = input.len() / input_stride as usize;
        check_limit("OMR bridge batch size", batch, self.capacity)?;
        let expected = batch * output_stride as usize;
        if output.len() != expected {
            return Err(CudaError::LengthMismatch {
                lhs: expected,
                rhs: output.len(),
            });
        }
        if expected == 0 {
            return Ok(None);
        }
        let count = expected as u32;
        Ok(Some((count, elementwise_config(count, self.ntt.max_grid)?)))
    }

    /// Sums four consecutive BR1 GLWEs per clue and overwrites one GLWE per clue.
    ///
    /// # Errors
    /// Rejects mismatched or incomplete batches, foreign streams and driver errors.
    ///
    /// # Correctness
    /// Input coefficients must be canonical under the first ring modulus.
    pub fn sum_four_to(
        &self,
        input: CudaView<'_, u32>,
        mut output: CudaViewMut<'_, u32>,
    ) -> Result<(), CudaError> {
        let Some((count, config)) =
            self.check_batch(&input, &output, 4 * self.glwe_len, self.glwe_len)?
        else {
            return Ok(());
        };
        // SAFETY: all four input GLWEs for each output were checked above.
        unsafe {
            self.ntt
                .stream
                .launch_builder(&self.sum)
                .arg(&input)
                .arg(&mut output)
                .arg(&count)
                .arg(&self.glwe_len)
                .arg(&self.ntt.modulus)
                .launch(config)?;
        }
        Ok(())
    }

    /// Extracts the constant coefficient from each rank-one GLWE into a compact LWE.
    ///
    /// # Errors
    /// Rejects mismatched or incomplete batches, foreign streams and driver errors.
    ///
    /// # Correctness
    /// Input coefficients must be canonical under the first ring modulus. The
    /// GLWE secret must have the active LWE prefix followed by zero coefficients.
    pub fn extract_to(
        &self,
        input: CudaView<'_, u32>,
        mut output: CudaViewMut<'_, u32>,
    ) -> Result<(), CudaError> {
        let Some((count, config)) =
            self.check_batch(&input, &output, self.glwe_len, self.lwe_len)?
        else {
            return Ok(());
        };
        // SAFETY: the checked views contain one whole GLWE and its bound LWE prefix per clue.
        unsafe {
            self.ntt
                .stream
                .launch_builder(&self.extract)
                .arg(&input)
                .arg(&mut output)
                .arg(&count)
                .arg(&self.ntt.n)
                .arg(&self.lwe_len)
                .arg(&self.ntt.modulus)
                .launch(config)?;
        }
        Ok(())
    }

    /// Rounds each compact LWE coefficient to `q=4096` with ties upward,
    /// including endpoint wrap, and widens it to the `u64` BR2 representation.
    ///
    /// # Errors
    /// Rejects mismatched or incomplete batches, foreign streams and driver errors.
    ///
    /// # Correctness
    /// Input coefficients must be canonical under the first ring modulus.
    pub fn switch_to(
        &self,
        input: CudaView<'_, u32>,
        mut output: CudaViewMut<'_, u64>,
    ) -> Result<(), CudaError> {
        let Some((count, config)) =
            self.check_batch(&input, &output, self.lwe_len, self.lwe_len)?
        else {
            return Ok(());
        };
        // SAFETY: the checked views have the same number of words and belong to one stream.
        unsafe {
            self.ntt
                .stream
                .launch_builder(&self.switch)
                .arg(&input)
                .arg(&mut output)
                .arg(&count)
                .arg(&self.ntt.modulus)
                .arg(&self.reciprocal)
                .launch(config)?;
        }
        Ok(())
    }
}
