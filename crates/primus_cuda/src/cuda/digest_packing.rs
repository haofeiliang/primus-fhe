use std::sync::Arc;

use cudarc::driver::{CudaFunction, CudaStream, CudaView, CudaViewMut, DeviceSlice, PushKernelArg};

use super::{
    CudaError, CudaNttPlan64, check_limit, elementwise_config, external_product::checked_batch_len,
    launch_grid_limit,
};

/// Expands compact F257 records into centered coefficient-domain public polynomials.
/// The binding retains the plan's stream and packing kernel and allocates no scratch.
pub struct CudaDigestPacking64 {
    stream: Arc<CudaStream>,
    kernel: CudaFunction,
    input_stride: usize,
    output_stride: u32,
    index_len: u32,
    payload_digits: u32,
    payload_rows: u32,
    batch_capacity: usize,
    modulus: u64,
    max_grid: u32,
}

impl CudaDigestPacking64 {
    /// Binds the continuous index/payload layout and maximum number of records.
    /// `index_len` fits the first polynomial; every payload row contains
    /// `payload_digits` coefficients and may cross polynomial boundaries.
    ///
    /// # Errors
    /// Rejects an index prefix longer than the plan's polynomial, zero payload
    /// dimensions or capacity, `q < 257`, excessive storage or launch dimensions,
    /// and driver errors.
    pub fn new(
        plan: &CudaNttPlan64,
        index_len: usize,
        payload_digits: usize,
        payload_rows: usize,
        batch_capacity: usize,
    ) -> Result<Self, CudaError> {
        let n = plan.poly_length();
        if index_len > n
            || payload_digits == 0
            || payload_rows == 0
            || batch_capacity == 0
            || plan.modulus() < 257
        {
            return Err(CudaError::InvalidParameters(
                "incompatible F257 packing geometry or modulus",
            ));
        }
        let input_stride = index_len
            .checked_add(payload_digits)
            .and_then(|len| len.checked_add(payload_rows))
            .ok_or(CudaError::InvalidParameters("F257 input length overflow"))?;
        let logical_length = payload_digits
            .checked_mul(payload_rows)
            .and_then(|len| len.checked_add(index_len))
            .ok_or(CudaError::InvalidParameters("F257 output length overflow"))?;
        let output_stride = logical_length
            .div_ceil(n)
            .checked_mul(n)
            .ok_or(CudaError::InvalidParameters("F257 padding length overflow"))?;
        checked_batch_len::<u16>(batch_capacity, input_stride)?;
        let output_capacity = checked_batch_len::<u64>(batch_capacity, output_stride)?;
        let stream = Arc::clone(plan.stream());
        let kernel = plan.inner.module.load_function("primus_digest_pack_u64")?;
        let max_grid = launch_grid_limit(&stream, &[(&kernel, 0)])?;
        elementwise_config(output_capacity, max_grid)?;
        Ok(Self {
            stream,
            kernel,
            input_stride,
            output_stride: output_stride as u32,
            index_len: index_len as u32,
            payload_digits: payload_digits as u32,
            payload_rows: payload_rows as u32,
            batch_capacity,
            modulus: plan.modulus(),
            max_grid,
        })
    }

    /// Packs `[index coefficients][payload digits][row weights]` records.
    ///
    /// Each output record contains the index prefix followed by the payload
    /// digits multiplied by each successive row weight in F257. Coefficients
    /// are lifted from `[-128,128]` into canonical residues under the plan's
    /// modulus, then padded with zeros to complete polynomials. The output
    /// layout is `[record][physical polynomial][coefficient]` and is overwritten.
    /// Submission adds no device allocation or host synchronization.
    ///
    /// # Errors
    /// Rejects foreign streams, incomplete input records, excessive batch size
    /// and mismatched output length before submission. Driver failures can leave
    /// partial output; deferred errors surface on synchronization or later calls.
    ///
    /// # Correctness
    /// Every input value must be a canonical F257 coefficient in `0..257`.
    /// Input and output must occupy distinct device storage.
    pub fn pack_to(
        &self,
        input: CudaView<'_, u16>,
        mut output: CudaViewMut<'_, u64>,
    ) -> Result<(), CudaError> {
        if !Arc::ptr_eq(input.stream(), &self.stream) || !Arc::ptr_eq(output.stream(), &self.stream)
        {
            return Err(CudaError::StreamMismatch);
        }
        if !input.len().is_multiple_of(self.input_stride) {
            return Err(CudaError::InvalidParameters(
                "F257 input ends with an incomplete record",
            ));
        }
        let batch = input.len() / self.input_stride;
        check_limit("F257 packing batch size", batch, self.batch_capacity)?;
        let count = batch * self.output_stride as usize;
        if output.len() != count {
            return Err(CudaError::LengthMismatch {
                lhs: count,
                rhs: output.len(),
            });
        }
        if batch == 0 {
            return Ok(());
        }
        let count = count as u32;
        // SAFETY: complete disjoint batches and all ABI extents are validated.
        // The kernel writes exactly count coefficients using size_t offsets.
        unsafe {
            self.stream
                .launch_builder(&self.kernel)
                .arg(&input)
                .arg(&mut output)
                .arg(&count)
                .arg(&self.index_len)
                .arg(&self.payload_digits)
                .arg(&self.payload_rows)
                .arg(&self.output_stride)
                .arg(&self.modulus)
                .launch(elementwise_config(count, self.max_grid)?)?;
        }
        Ok(())
    }
}
