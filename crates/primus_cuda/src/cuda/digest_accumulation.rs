use std::sync::Arc;

use cudarc::driver::{CudaFunction, CudaViewMut, PushKernelArg};
use primus_lattice::GlweSize;

use super::{
    CudaError, CudaNttPlan64, NttPlan, check_limit, elementwise_config,
    external_product::checked_batch_len, launch_grid_limit,
};

/// Bound geometry for adding batched flag products to device-resident digest sums.
/// Buffers are caller-owned and use the plan's stream.
pub struct CudaDigestAccumulation64 {
    ntt: Arc<NttPlan<u64>>,
    kernel: CudaFunction,
    glwe_size: GlweSize,
    physical_count: u32,
    batch_capacity: usize,
    sum_count: u32,
    public_stride: usize,
    modulus_bits: u32,
    reciprocal: u64,
}

impl CudaDigestAccumulation64 {
    /// Binds the flag shape and the number of physical public polynomials per record.
    ///
    /// # Errors
    /// Rejects a polynomial size different from the plan, zero physical count or
    /// capacity, excessive storage or grid dimensions, and driver errors.
    pub fn new(
        plan: &CudaNttPlan64,
        glwe_size: GlweSize,
        physical_count: usize,
        batch_capacity: usize,
    ) -> Result<Self, CudaError> {
        if glwe_size.poly_length().get() != plan.poly_length()
            || physical_count == 0
            || batch_capacity == 0
        {
            return Err(CudaError::InvalidParameters(
                "incompatible digest accumulation geometry",
            ));
        }
        let sum_count = checked_batch_len::<u64>(physical_count, glwe_size.glwe_len())?;
        let public_stride = physical_count * plan.poly_length();
        let flag_capacity = checked_batch_len::<u64>(batch_capacity, glwe_size.glwe_len())?;
        let public_capacity = checked_batch_len::<u64>(batch_capacity, public_stride)?;
        let ntt = Arc::clone(&plan.inner);
        let kernel = ntt.module.load_function("primus_digest_accumulate_u64")?;
        let max_grid = launch_grid_limit(&ntt.stream, &[(&kernel, 0)])?;
        check_limit(
            "digest transform grid size",
            (flag_capacity.max(public_capacity) / ntt.n) as usize,
            max_grid as usize,
        )?;
        elementwise_config(sum_count, max_grid)?;
        Ok(Self {
            ntt,
            kernel,
            glwe_size,
            physical_count: physical_count as u32,
            batch_capacity,
            sum_count,
            public_stride,
            modulus_bits: plan.modulus_bits,
            reciprocal: plan.reciprocal,
        })
    }

    /// Adds each full encrypted flag times every public polynomial for its record.
    ///
    /// `sums` is `[physical][GLWE component][coefficient]` in NTT form and must
    /// already be initialized. `flags` is `[record][GLWE component][coefficient]`
    /// and `public_polynomials` is `[record][physical][coefficient]`. Both input
    /// views start in coefficient form and are overwritten with their NTTs.
    /// A validated empty batch leaves `sums` untouched.
    ///
    /// # Errors
    /// Rejects malformed shapes, foreign streams and excessive batches before
    /// submission. A driver failure can leave a partially transformed batch.
    ///
    /// # Correctness
    /// All coefficients are canonical under the plan's modulus. NTT sums must
    /// use the same roots and evaluation order. Each public polynomial must
    /// already contain the full packed and padded physical coefficient stream.
    pub fn accumulate_assign(
        &self,
        mut sums: CudaViewMut<'_, u64>,
        mut flags: CudaViewMut<'_, u64>,
        mut public_polynomials: CudaViewMut<'_, u64>,
    ) -> Result<(), CudaError> {
        let ntt = &self.ntt;
        ntt.check_view_stream(&sums)?;
        ntt.check_view_stream(&flags)?;
        ntt.check_view_stream(&public_polynomials)?;
        if sums.len() != self.sum_count as usize {
            return Err(CudaError::LengthMismatch {
                lhs: self.sum_count as usize,
                rhs: sums.len(),
            });
        }
        let glwe_len = self.glwe_size.glwe_len();
        if !flags.len().is_multiple_of(glwe_len) {
            return Err(CudaError::IncompleteGlweBatch {
                length: flags.len(),
                glwe_length: glwe_len,
            });
        }
        let clues = flags.len() / glwe_len;
        check_limit("digest accumulation batch size", clues, self.batch_capacity)?;
        let public_len = clues * self.public_stride;
        if public_polynomials.len() != public_len {
            return Err(CudaError::LengthMismatch {
                lhs: public_len,
                rhs: public_polynomials.len(),
            });
        }
        if clues == 0 {
            return Ok(());
        }
        let config = elementwise_config(self.sum_count, ntt.max_grid)?;
        let flag_polynomials = flags.len() as u32 / ntt.n;
        ntt.transform_batch(flags.slice_mut(..), flag_polynomials, false)?;
        ntt.transform_batch(
            public_polynomials.slice_mut(..),
            public_len as u32 / ntt.n,
            false,
        )?;
        let flags = flags.as_view();
        let public = public_polynomials.as_view();
        let clues = clues as u32;
        let components = self.glwe_size.component_count() as u32;
        // SAFETY: the three views are disjoint, in the same stream allocation
        // domain, and checked for complete physical polynomials and components.
        unsafe {
            ntt.stream
                .launch_builder(&self.kernel)
                .arg(&mut sums)
                .arg(&flags)
                .arg(&public)
                .arg(&self.sum_count)
                .arg(&ntt.n)
                .arg(&components)
                .arg(&self.physical_count)
                .arg(&clues)
                .arg(&ntt.modulus)
                .arg(&self.modulus_bits)
                .arg(&self.reciprocal)
                .launch(config)?;
        }
        Ok(())
    }
}
