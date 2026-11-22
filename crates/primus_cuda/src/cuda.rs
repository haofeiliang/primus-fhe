use std::{mem::size_of, sync::Arc};

use cudarc::{
    driver::{
        CudaFunction, CudaModule, CudaSlice, CudaStream, CudaView, CudaViewMut, DeviceRepr,
        DeviceSlice, DriverError, LaunchConfig, PushKernelArg, sys,
    },
    nvrtc::Ptx,
};
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable};

mod block_rotation;
mod external_product;
pub use block_rotation::{CudaBlockBlindRotationWorkspace32, CudaBlockBlindRotationWorkspace64};
pub use external_product::{CudaExternalProductWorkspace32, CudaExternalProductWorkspace64};

const THREADS: u32 = 256;
const MAX_POLYNOMIAL_LENGTH: usize = 2048;
const PTX: &str = include_str!(concat!(env!("OUT_DIR"), "/primus_cuda.ptx"));

/// A rejected CUDA binding, launch geometry, or driver operation.
#[derive(Debug, thiserror::Error)]
pub enum CudaError {
    /// The polynomial exceeds the single-block kernel's supported length.
    #[error("CUDA polynomial length {length} exceeds {maximum}")]
    UnsupportedPolynomialLength {
        /// Rejected coefficient count.
        length: usize,
        /// Maximum supported coefficient count.
        maximum: usize,
    },
    /// The view ends with an incomplete polynomial.
    #[error("CUDA batch length {length} is not a multiple of {polynomial_length}")]
    IncompletePolynomialBatch {
        /// Rejected coefficient count.
        length: usize,
        /// Coefficient count of one polynomial.
        polynomial_length: usize,
    },
    /// The coefficient view ends with an incomplete GLWE ciphertext.
    #[error("CUDA batch length {length} is not a multiple of GLWE length {glwe_length}")]
    IncompleteGlweBatch {
        /// Rejected coefficient count.
        length: usize,
        /// Coefficient count of one GLWE ciphertext.
        glwe_length: usize,
    },
    /// The coefficient view ends with an incomplete LWE ciphertext.
    #[error("CUDA batch length {length} is not a multiple of LWE length {lwe_length}")]
    IncompleteLweBatch {
        /// Rejected coefficient count.
        length: usize,
        /// Coefficient count of one LWE ciphertext.
        lwe_length: usize,
    },
    /// Operands of the same operation have different lengths.
    #[error("CUDA operand lengths differ: {lhs} and {rhs}")]
    LengthMismatch {
        /// Expected coefficient count.
        lhs: usize,
        /// Observed coefficient count.
        rhs: usize,
    },
    /// A device view was allocated on a different stream from the plan.
    #[error("CUDA view and plan must share the same stream allocation owner")]
    StreamMismatch,
    /// A per-thread default stream does not provide stable queue identity.
    #[error("per-thread CUDA streams are not supported")]
    UnsupportedStream,
    /// A launch exceeds an ABI or device limit.
    #[error("CUDA {resource} requires {requested}, limit is {limit}")]
    Limit {
        /// Resource or ABI field being checked.
        resource: &'static str,
        /// Requested count or size.
        requested: usize,
        /// Available count or size.
        limit: usize,
    },
    /// Host table metadata cannot be used by the selected kernel.
    #[error("invalid CUDA parameters: {0}")]
    InvalidParameters(&'static str),
    /// An immediate or previously deferred CUDA driver error.
    #[error(transparent)]
    Driver(#[from] DriverError),
}

fn check_limit(resource: &'static str, requested: usize, limit: usize) -> Result<(), CudaError> {
    if requested > limit {
        return Err(CudaError::Limit {
            resource,
            requested,
            limit,
        });
    }
    Ok(())
}

fn launch_grid_limit(
    stream: &CudaStream,
    functions: &[(&CudaFunction, usize)],
) -> Result<u32, CudaError> {
    use sys::{
        CUdevice_attribute as DeviceAttribute, CUfunction_attribute_enum as FunctionAttribute,
    };

    let context = stream.context();
    let attribute = |name| -> Result<usize, CudaError> {
        usize::try_from(context.attribute(name)?)
            .map_err(|_| CudaError::InvalidParameters("negative device limit"))
    };
    check_limit(
        "threads per block",
        THREADS as usize,
        attribute(DeviceAttribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK)?,
    )?;
    check_limit(
        "block x dimension",
        THREADS as usize,
        attribute(DeviceAttribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X)?,
    )?;
    let shared_limit = attribute(DeviceAttribute::CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK)?;
    for &(function, shared_mem_bytes) in functions {
        let threads = usize::try_from(
            function.get_attribute(FunctionAttribute::CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK)?,
        )
        .map_err(|_| CudaError::InvalidParameters("negative kernel thread limit"))?;
        check_limit("kernel threads per block", THREADS as usize, threads)?;
        let static_shared = usize::try_from(function.shared_size_bytes()?)
            .map_err(|_| CudaError::InvalidParameters("negative kernel shared memory"))?;
        check_limit(
            "shared memory bytes",
            shared_mem_bytes,
            shared_limit.saturating_sub(static_shared),
        )?;
    }
    let max_grid = attribute(DeviceAttribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X)?;
    u32::try_from(max_grid).map_err(|_| CudaError::InvalidParameters("grid limit exceeds u32"))
}

fn checked_count<T>(length: usize) -> Result<u32, CudaError> {
    // Cover both the kernel's u32 count and representable byte offsets, even
    // on a host whose address width is narrower than the device's pointers.
    let limit = (u32::MAX as usize).min(isize::MAX as usize / size_of::<T>());
    check_limit("coefficient count", length, limit)?;
    Ok(length as u32)
}

fn check_stream(stream: &CudaStream) -> Result<(), CudaError> {
    const CU_STREAM_PER_THREAD: usize = 2;
    // The per-thread pseudo-handle can resolve to different queues when the
    // plan is moved between threads, without activating cudarc's event tracking.
    if stream.cu_stream() as usize == CU_STREAM_PER_THREAD {
        return Err(CudaError::UnsupportedStream);
    }
    Ok(())
}

fn elementwise_config(count: u32, max_grid: u32) -> Result<LaunchConfig, CudaError> {
    let blocks = count.div_ceil(THREADS);
    check_limit("grid x dimension", blocks as usize, max_grid as usize)?;
    Ok(LaunchConfig {
        grid_dim: (blocks, 1, 1),
        block_dim: (THREADS, 1, 1),
        shared_mem_bytes: 0,
    })
}

struct NttPlan<T> {
    stream: Arc<CudaStream>,
    module: Arc<CudaModule>,
    roots: CudaSlice<T>,
    root_precon: CudaSlice<T>,
    inverse_roots: CudaSlice<T>,
    inverse_root_precon: CudaSlice<T>,
    forward: CudaFunction,
    inverse: CudaFunction,
    multiply: CudaFunction,
    add_product: CudaFunction,
    multiply_monomial: CudaFunction,
    n: u32,
    modulus: T,
    inverse_n: T,
    inverse_n_precon: T,
    max_grid: u32,
    shared_mem_bytes: u32,
}

impl<T: Copy + DeviceRepr + Into<u128> + TryFrom<u128>> NttPlan<T> {
    fn new<Table: MonomialNttTable<ValueT = T>>(
        stream: &Arc<CudaStream>,
        table: &Table,
        [
            forward_name,
            inverse_name,
            multiply_name,
            add_product_name,
            monomial_name,
        ]: [&str; 5],
    ) -> Result<Self, CudaError> {
        check_stream(stream)?;
        let n = table.poly_length().get();
        if n > MAX_POLYNOMIAL_LENGTH {
            return Err(CudaError::UnsupportedPolynomialLength {
                length: n,
                maximum: MAX_POLYNOMIAL_LENGTH,
            });
        }
        let roots = table.root_powers();
        let inverse_roots = table.inv_root_powers();
        if roots.len() != n || inverse_roots.len() != n {
            return Err(CudaError::InvalidParameters("root table length mismatch"));
        }
        let modulus = table.modulus();
        let q: u128 = modulus.into();
        if q <= 1 || q % n as u128 != 1 {
            return Err(CudaError::InvalidParameters("N must divide q - 1"));
        }
        let bits = size_of::<T>() * 8;
        let shoup = |value: T| -> Result<T, CudaError> {
            T::try_from((value.into() << bits) / q)
                .map_err(|_| CudaError::InvalidParameters("Shoup factor overflow"))
        };
        let root_precon = roots
            .iter()
            .copied()
            .map(shoup)
            .collect::<Result<Vec<_>, _>>()?;
        let inverse_root_precon = inverse_roots
            .iter()
            .copied()
            .map(shoup)
            .collect::<Result<Vec<_>, _>>()?;
        // q = k*N + 1 implies N * (q-k) = 1 mod q.
        let inverse_n = T::try_from(q - (q - 1) / n as u128)
            .map_err(|_| CudaError::InvalidParameters("inverse length overflow"))?;
        let inverse_n_precon = shoup(inverse_n)?;
        let module = stream.context().load_module(Ptx::from_src(PTX))?;
        let forward = module.load_function(forward_name)?;
        let inverse = module.load_function(inverse_name)?;
        let multiply = module.load_function(multiply_name)?;
        let add_product = module.load_function(add_product_name)?;
        let multiply_monomial = module.load_function(monomial_name)?;
        let shared_mem_bytes = (n * size_of::<T>()) as u32;
        let max_grid = launch_grid_limit(
            stream,
            &[
                (&forward, shared_mem_bytes as usize),
                (&inverse, shared_mem_bytes as usize),
                (&multiply, 0),
                (&add_product, 0),
                (&multiply_monomial, 0),
            ],
        )?;
        Ok(Self {
            roots: stream.clone_htod(roots)?,
            root_precon: stream.clone_htod(&root_precon)?,
            inverse_roots: stream.clone_htod(inverse_roots)?,
            inverse_root_precon: stream.clone_htod(&inverse_root_precon)?,
            stream: Arc::clone(stream),
            module,
            forward,
            inverse,
            multiply,
            add_product,
            multiply_monomial,
            n: n as u32,
            modulus,
            inverse_n,
            inverse_n_precon,
            max_grid,
            shared_mem_bytes,
        })
    }
}

impl<T: DeviceRepr> NttPlan<T> {
    fn check_view_stream<U>(&self, view: &impl DeviceSlice<U>) -> Result<(), CudaError> {
        // The allocation has one read event and one write event. Submissions
        // through several plans must not overwrite either event from unrelated
        // queues. The allocation and plan share the same ordered queue.
        if !Arc::ptr_eq(view.stream(), &self.stream) {
            return Err(CudaError::StreamMismatch);
        }
        Ok(())
    }

    fn transform_assign(&self, values: CudaViewMut<'_, T>, inverse: bool) -> Result<(), CudaError> {
        self.check_view_stream(&values)?;
        let count = checked_count::<T>(values.len())?;
        self.check_full_polynomials(count)?;
        let blocks = count / self.n;
        check_limit("grid x dimension", blocks as usize, self.max_grid as usize)?;
        self.transform_batch(values, blocks, inverse)
    }

    // The caller has checked this extent, the device grid limit and stream.
    fn transform_batch(
        &self,
        mut values: CudaViewMut<'_, T>,
        blocks: u32,
        inverse: bool,
    ) -> Result<(), CudaError> {
        debug_assert_eq!(values.len(), blocks as usize * self.n as usize);
        if blocks == 0 {
            return Ok(());
        }
        let (kernel, roots, precon) = if inverse {
            (
                &self.inverse,
                &self.inverse_roots,
                &self.inverse_root_precon,
            )
        } else {
            (&self.forward, &self.roots, &self.root_precon)
        };
        let mut launch = self.stream.launch_builder(kernel);
        launch
            .arg(&mut values)
            .arg(roots)
            .arg(precon)
            .arg(&self.n)
            .arg(&self.modulus);
        if inverse {
            launch.arg(&self.inverse_n).arg(&self.inverse_n_precon);
        }
        // SAFETY: these fixed PTX entry points take exactly the typed arguments
        // above. Each block accesses one complete N-element polynomial; roots
        // have N entries and dynamic shared memory holds N elements. The view
        // uses the allocation's stream, which orders launch and deallocation.
        unsafe {
            launch.launch(LaunchConfig {
                grid_dim: (blocks, 1, 1),
                block_dim: (THREADS, 1, 1),
                shared_mem_bytes: self.shared_mem_bytes,
            })?;
        }
        Ok(())
    }

    fn check_full_polynomials(&self, count: u32) -> Result<(), CudaError> {
        if !count.is_multiple_of(self.n) {
            return Err(CudaError::IncompletePolynomialBatch {
                length: count as usize,
                polynomial_length: self.n as usize,
            });
        }
        Ok(())
    }

    fn check_operand_length(
        &self,
        expected: usize,
        operand: &CudaView<'_, T>,
    ) -> Result<(), CudaError> {
        self.check_view_stream(operand)?;
        if expected != operand.len() {
            return Err(CudaError::LengthMismatch {
                lhs: expected,
                rhs: operand.len(),
            });
        }
        Ok(())
    }

    fn matching_count(
        &self,
        output: &CudaViewMut<'_, T>,
        operand: &CudaView<'_, T>,
    ) -> Result<u32, CudaError> {
        self.check_view_stream(output)?;
        self.check_operand_length(output.len(), operand)?;
        checked_count::<T>(output.len())
    }

    fn mul_monomial_to(
        &self,
        input: CudaView<'_, T>,
        degree: usize,
        mut output: CudaViewMut<'_, T>,
    ) -> Result<(), CudaError> {
        let count = self.matching_count(&output, &input)?;
        self.check_full_polynomials(count)?;
        if count == 0 {
            return Ok(());
        }
        let config = elementwise_config(count, self.max_grid)?;
        let degree = (degree % (2 * self.n as usize)) as u32;
        // SAFETY: the kernel accesses disjoint input/output views from the plan's
        // stream. Each complete polynomial is an independent negacyclic ring, and
        // the host reduced the degree modulo 2N before passing it to the typed ABI.
        unsafe {
            self.stream
                .launch_builder(&self.multiply_monomial)
                .arg(&input)
                .arg(&mut output)
                .arg(&count)
                .arg(&self.n)
                .arg(&degree)
                .arg(&self.modulus)
                .launch(config)?;
        }
        Ok(())
    }
}

/// A CUDA NTT plan matching one CPU `U32NttTable`'s roots and normalization.
///
/// The plan retains its stream and uploaded roots. Transform views contain a
/// flat batch of complete polynomials, each of length `poly_length()`. No device
/// allocation or host synchronization is added by the arithmetic methods.
pub struct CudaNttPlan32 {
    inner: NttPlan<u32>,
}

/// A CUDA NTT plan matching one CPU `U64NttTable`'s roots and normalization.
///
/// This single-block implementation supports `N <= 2048` and `q < 2^62`.
/// The plan retains its stream and uploaded roots; arithmetic methods add no
/// device allocation or host synchronization.
pub struct CudaNttPlan64 {
    inner: NttPlan<u64>,
    modulus_bits: u32,
    reciprocal: u64,
}

macro_rules! plan_methods {
    ($plan:ident, $word:ty) => {
        impl $plan {
            /// Returns the coefficient count of each polynomial in a transform batch.
            #[must_use]
            pub fn poly_length(&self) -> usize {
                self.inner.n as usize
            }

            /// Returns the coefficient modulus shared by this plan's operations.
            #[must_use]
            pub fn modulus(&self) -> $word {
                self.inner.modulus
            }

            /// Returns the stream for operand allocation and kernel submission.
            #[must_use]
            pub fn stream(&self) -> &Arc<CudaStream> {
                &self.inner.stream
            }

            /// Submits canonical forward NTTs for a flat batch of complete polynomials.
            /// Empty batches are accepted. Outputs are canonical bit-reversed evaluations.
            ///
            /// # Errors
            /// Rejects a foreign allocation stream, incomplete polynomial, excessive
            /// count/grid, or driver failure. Checks precede submission.
            ///
            /// # Correctness
            /// Every coefficient must be in `[0, self.modulus())`.
            pub fn transform_assign(
                &self,
                values: CudaViewMut<'_, $word>,
            ) -> Result<(), CudaError> {
                self.inner.transform_assign(values, false)
            }

            /// Submits normalized inverse NTTs for a flat batch of complete polynomials.
            /// Empty batches are accepted. Outputs are canonical ascending-power coefficients.
            ///
            /// # Errors
            /// Rejects a foreign allocation stream, incomplete polynomial, excessive
            /// count/grid, or driver failure. Checks precede submission.
            ///
            /// # Correctness
            /// Inputs must be canonical evaluations using this plan's exact roots,
            /// bit-reversed order and unnormalized forward convention.
            pub fn inverse_transform_assign(
                &self,
                values: CudaViewMut<'_, $word>,
            ) -> Result<(), CudaError> {
                self.inner.transform_assign(values, true)
            }

            /// Multiplies each coefficient-domain polynomial by `X^degree` modulo `X^N + 1`.
            /// Uses the same degree for the whole batch, reduced modulo `2N`.
            /// Overwrites `output` with canonical residues and accepts an empty batch.
            ///
            /// # Errors
            /// Rejects unequal lengths, incomplete polynomials, foreign allocation
            /// streams, excessive count/grid, or driver failure.
            ///
            /// # Correctness
            /// Input polynomials must be contiguous and in ascending coefficient
            /// order, with residues in `[0, self.modulus())`.
            pub fn mul_monomial_to(
                &self,
                input: CudaView<'_, $word>,
                degree: usize,
                output: CudaViewMut<'_, $word>,
            ) -> Result<(), CudaError> {
                self.inner.mul_monomial_to(input, degree, output)
            }
        }
    };
}

plan_methods!(CudaNttPlan32, u32);
plan_methods!(CudaNttPlan64, u64);

impl CudaNttPlan32 {
    /// Prepares a plan from the CPU table's canonical roots, for `N <= 2048`.
    ///
    /// # Errors
    /// Returns unsupported geometry, device-limit, module-loading or upload errors.
    pub fn new(stream: &Arc<CudaStream>, table: &U32NttTable) -> Result<Self, CudaError> {
        Ok(Self {
            inner: NttPlan::new(
                stream,
                table,
                [
                    "primus_forward_u32",
                    "primus_inverse_u32",
                    "primus_mul_u32",
                    "primus_mul_add_u32",
                    "primus_mul_monomial_u32",
                ],
            )?,
        })
    }

    /// Submits `lhs[i] *= rhs[i] mod q`, returning canonical residues.
    /// Equal-length slices of any size, including zero, are accepted.
    ///
    /// # Errors
    /// Rejects unequal lengths, foreign allocation streams, excessive count/grid
    /// or driver failure. Checks precede submission.
    ///
    /// # Correctness
    /// Both inputs must be canonical under this plan's modulus. For NTT products,
    /// both must additionally use this plan's roots, order and normalization.
    pub fn mul_assign(
        &self,
        mut lhs: CudaViewMut<'_, u32>,
        rhs: CudaView<'_, u32>,
    ) -> Result<(), CudaError> {
        let count = self.inner.matching_count(&lhs, &rhs)?;
        if count == 0 {
            return Ok(());
        }
        let config = elementwise_config(count, self.inner.max_grid)?;
        // SAFETY: the kernel's pointer/scalar ABI matches these arguments;
        // checked streams and equal lengths cover every count-bounded access.
        unsafe {
            self.inner
                .stream
                .launch_builder(&self.inner.multiply)
                .arg(&mut lhs)
                .arg(&rhs)
                .arg(&count)
                .arg(&self.inner.modulus)
                .launch(config)?;
        }
        Ok(())
    }

    /// Adds `lhs[i] * rhs[i]` to `acc[i]` modulo `q`, leaving canonical residues.
    /// Equal-length operands of any size, including zero, are accepted.
    ///
    /// # Errors
    /// Rejects unequal lengths, foreign allocation streams, excessive count/grid
    /// or driver failure.
    ///
    /// # Correctness
    /// All three operands must contain canonical residues under this plan's
    /// modulus. NTT operands must share its roots, order and normalization.
    pub fn add_mul_assign(
        &self,
        mut acc: CudaViewMut<'_, u32>,
        lhs: CudaView<'_, u32>,
        rhs: CudaView<'_, u32>,
    ) -> Result<(), CudaError> {
        let count = self.inner.matching_count(&acc, &lhs)?;
        self.inner.check_operand_length(acc.len(), &rhs)?;
        if count == 0 {
            return Ok(());
        }
        let config = elementwise_config(count, self.inner.max_grid)?;
        // SAFETY: the typed ABI reads count coefficients from each input and
        // mutates only acc. Equal lengths and the shared allocation stream were checked.
        unsafe {
            self.inner
                .stream
                .launch_builder(&self.inner.add_product)
                .arg(&mut acc)
                .arg(&lhs)
                .arg(&rhs)
                .arg(&count)
                .arg(&self.inner.modulus)
                .launch(config)?;
        }
        Ok(())
    }
}

impl CudaNttPlan64 {
    /// Prepares a plan from the CPU table's canonical roots, for `N <= 2048`.
    ///
    /// # Errors
    /// Returns unsupported geometry/modulus, device-limit, module-loading or upload errors.
    pub fn new(stream: &Arc<CudaStream>, table: &U64NttTable) -> Result<Self, CudaError> {
        let modulus = table.modulus();
        let modulus_bits = u64::BITS - modulus.leading_zeros();
        if modulus_bits > 62 {
            return Err(CudaError::InvalidParameters(
                "u64 modulus requires at most 62 bits",
            ));
        }
        let reciprocal = ((1u128 << (2 * modulus_bits)) / u128::from(modulus)) as u64;
        Ok(Self {
            inner: NttPlan::new(
                stream,
                table,
                [
                    "primus_forward_u64",
                    "primus_inverse_u64",
                    "primus_mul_u64",
                    "primus_mul_add_u64",
                    "primus_mul_monomial_u64",
                ],
            )?,
            modulus_bits,
            reciprocal,
        })
    }

    /// Submits `lhs[i] *= rhs[i] mod q`, returning canonical residues.
    /// Equal-length slices of any size, including zero, are accepted.
    ///
    /// # Errors
    /// Rejects unequal lengths, foreign allocation streams, excessive count/grid
    /// or driver failure. Checks precede submission.
    ///
    /// # Correctness
    /// Both inputs must be canonical under this plan's modulus. For NTT products,
    /// both must additionally use this plan's roots, order and normalization.
    pub fn mul_assign(
        &self,
        mut lhs: CudaViewMut<'_, u64>,
        rhs: CudaView<'_, u64>,
    ) -> Result<(), CudaError> {
        let count = self.inner.matching_count(&lhs, &rhs)?;
        if count == 0 {
            return Ok(());
        }
        let config = elementwise_config(count, self.inner.max_grid)?;
        // SAFETY: the typed ABI and count-bounded accesses match the kernel;
        // preparation established q_bits <= 62 and the exact reciprocal.
        unsafe {
            self.inner
                .stream
                .launch_builder(&self.inner.multiply)
                .arg(&mut lhs)
                .arg(&rhs)
                .arg(&count)
                .arg(&self.inner.modulus)
                .arg(&self.modulus_bits)
                .arg(&self.reciprocal)
                .launch(config)?;
        }
        Ok(())
    }

    /// Adds `lhs[i] * rhs[i]` to `acc[i]` modulo `q`, leaving canonical residues.
    /// Equal-length operands of any size, including zero, are accepted.
    ///
    /// # Errors
    /// Rejects unequal lengths, foreign allocation streams, excessive count/grid
    /// or driver failure.
    ///
    /// # Correctness
    /// All three operands must contain canonical residues under this plan's
    /// modulus. NTT operands must share its roots, order and normalization.
    pub fn add_mul_assign(
        &self,
        mut acc: CudaViewMut<'_, u64>,
        lhs: CudaView<'_, u64>,
        rhs: CudaView<'_, u64>,
    ) -> Result<(), CudaError> {
        let count = self.inner.matching_count(&acc, &lhs)?;
        self.inner.check_operand_length(acc.len(), &rhs)?;
        if count == 0 {
            return Ok(());
        }
        let config = elementwise_config(count, self.inner.max_grid)?;
        // SAFETY: the typed ABI reads count coefficients from each input and
        // mutates only acc. Preparation established the Barrett parameters.
        unsafe {
            self.inner
                .stream
                .launch_builder(&self.inner.add_product)
                .arg(&mut acc)
                .arg(&lhs)
                .arg(&rhs)
                .arg(&count)
                .arg(&self.inner.modulus)
                .arg(&self.modulus_bits)
                .arg(&self.reciprocal)
                .launch(config)?;
        }
        Ok(())
    }
}

/// Copies host words to CUDA, adds one with wrapping arithmetic, and downloads.
///
/// This deliberately allocates and synchronizes for an installation smoke test.
/// Empty input returns an empty vector without launching a kernel.
///
/// # Errors
/// Returns an excessive count/grid, device-limit, allocation, launch or copy error.
pub fn cuda_smoke(stream: &Arc<CudaStream>, input: &[u32]) -> Result<Vec<u32>, CudaError> {
    check_stream(stream)?;
    let count = checked_count::<u32>(input.len())?;
    if count == 0 {
        return Ok(Vec::new());
    }
    let module = stream.context().load_module(Ptx::from_src(PTX))?;
    let kernel = module.load_function("primus_smoke")?;
    let max_grid = launch_grid_limit(stream, &[(&kernel, 0)])?;
    let config = elementwise_config(count, max_grid)?;
    let input = stream.clone_htod(input)?;
    let mut output = stream.alloc_zeros::<u32>(count as usize)?;
    // SAFETY: the fixed smoke kernel reads count u32s and writes exactly count
    // wrapping increments; both allocations have that length and this context.
    unsafe {
        stream
            .launch_builder(&kernel)
            .arg(&input)
            .arg(&mut output)
            .arg(&count)
            .launch(config)?;
    }
    let mut result = vec![0; input.len()];
    stream.memcpy_dtoh(&output, &mut result)?;
    // cudarc synchronizes the pageable host copy in a drop guard and records
    // synchronization errors on the context.
    stream.context().check_err()?;
    Ok(result)
}
