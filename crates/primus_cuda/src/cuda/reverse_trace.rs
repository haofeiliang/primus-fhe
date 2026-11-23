use std::sync::Arc;

use cudarc::driver::{CudaFunction, CudaSlice, CudaView, CudaViewMut, PushKernelArg};
use primus_glwe::NttGlweTraceKey;
use primus_lattice::GlweSize;

use super::{
    CudaError, CudaGlweKeySwitchingWorkspace64, CudaNttPlan64, NttPlan, check_limit,
    elementwise_config, key_switch::GlweKeySwitch, launch_grid_limit,
};

struct TraceStage {
    degree: u32,
    key: CudaSlice<u64>,
}

/// Resident keys and reusable scratch for batched reverse GLWE trace.
///
/// Inputs and outputs are flat coefficient-domain batches in mask-then-body
/// order. All automorphisms share one key-switching decomposition workspace;
/// evaluation adds no device allocation or host synchronization.
pub struct CudaReverseTraceWorkspace64 {
    ntt: Arc<NttPlan<u64>>,
    size: GlweSize,
    batch_capacity: usize,
    stages: Vec<TraceStage>,
    key_switch: GlweKeySwitch<u64>,
    halved: CudaSlice<u64>,
    permuted: CudaSlice<u64>,
    prepare: CudaFunction,
    add: CudaFunction,
}

impl CudaReverseTraceWorkspace64 {
    /// Uploads the trace keys and reserves scratch for `batch_capacity` GLWEs.
    /// The workspace retains the plan's stream, roots and kernels.
    ///
    /// # Errors
    /// Rejects zero capacity, incompatible key layouts or decomposition bases,
    /// excessive device or ABI limits, and driver failures.
    ///
    /// # Correctness
    /// The trace key must use this plan's exact NTT roots, order and normalization.
    pub fn new(
        plan: &CudaNttPlan64,
        key: &NttGlweTraceKey<u64>,
        batch_capacity: usize,
    ) -> Result<Self, CudaError> {
        let size = key.glwe_size();
        let mut material = key.reverse_key_switching_keys();
        let (first_degree, first_key) = material.next().ok_or(CudaError::InvalidParameters(
            "reverse trace requires at least one automorphism key",
        ))?;
        // Every stage reuses the first key's decomposition and buffer layout.
        // Check this once before upload rather than in the evaluation loop.
        for (degree, stage_key) in key.reverse_key_switching_keys() {
            if degree >= 2 * plan.poly_length()
                || degree & 1 == 0
                || stage_key.input_size() != size
                || stage_key.output_size().glwe_size() != size
                || stage_key.output_size() != first_key.output_size()
                || stage_key.basis() != first_key.basis()
                || stage_key.as_slice().len() != first_key.as_slice().len()
            {
                return Err(CudaError::InvalidParameters(
                    "reverse trace requires matching automorphism key layouts and bases",
                ));
            }
        }
        let CudaGlweKeySwitchingWorkspace64 {
            inner: key_switch,
            key: uploaded,
        } = CudaGlweKeySwitchingWorkspace64::new(plan, first_key, batch_capacity)?;
        let ntt = Arc::clone(&plan.inner);
        let prepare = ntt
            .module
            .load_function("primus_reverse_trace_prepare_u64")?;
        let add = ntt.module.load_function("primus_reverse_trace_add_u64")?;
        launch_grid_limit(&ntt.stream, &[(&prepare, 0), (&add, 0)])?;
        let length = batch_capacity * size.glwe_len();
        elementwise_config(length as u32, ntt.max_grid)?;
        let mut stages = Vec::with_capacity(key.automorphism_count());
        stages.push(TraceStage {
            degree: first_degree as u32,
            key: uploaded,
        });
        for (degree, stage_key) in material {
            stages.push(TraceStage {
                degree: degree as u32,
                key: ntt.stream.clone_htod(stage_key.as_slice())?,
            });
        }
        Ok(Self {
            halved: ntt.stream.alloc_zeros(length)?,
            permuted: ntt.stream.alloc_zeros(length)?,
            ntt,
            size,
            batch_capacity,
            stages,
            key_switch,
            prepare,
            add,
        })
    }

    /// Applies the CPU key's full reverse trace to every lane and overwrites `output`.
    /// Each stage halves the current ciphertext before its automorphism and key
    /// switch, in the key's reverse evaluation order. Output coefficients are
    /// canonical and remain in device memory.
    ///
    /// # Errors
    /// Rejects views from another stream, unequal lengths, incomplete GLWEs or
    /// a batch exceeding capacity before submitting any work. A driver failure
    /// may leave part of the output written; deferred errors surface on stream
    /// synchronization or later driver operations.
    ///
    /// # Correctness
    /// Input coefficients must be canonical modulo the bound plan's modulus.
    /// Input and output must occupy distinct device storage.
    pub fn apply_to(
        &mut self,
        input: CudaView<'_, u64>,
        mut output: CudaViewMut<'_, u64>,
    ) -> Result<(), CudaError> {
        let ntt = &self.ntt;
        let count = ntt.matching_count(&output, &input)?;
        let glwe_length = self.size.glwe_len();
        if !input.len().is_multiple_of(glwe_length) {
            return Err(CudaError::IncompleteGlweBatch {
                length: input.len(),
                glwe_length,
            });
        }
        let batch_size = input.len() / glwe_length;
        check_limit("GLWE batch size", batch_size, self.batch_capacity)?;
        if count == 0 {
            return Ok(());
        }
        let length = count as usize;
        let config = elementwise_config(count, ntt.max_grid)?;
        for (index, stage) in self.stages.iter().enumerate() {
            {
                let current = if index == 0 {
                    input.slice(..)
                } else {
                    output.as_view()
                };
                let mut halved = self.halved.slice_mut(..length);
                let mut permuted = self.permuted.slice_mut(..length);
                // SAFETY: all three batches are complete and disjoint. The odd
                // degree permutes each polynomial; no scatter write overlaps.
                unsafe {
                    ntt.stream
                        .launch_builder(&self.prepare)
                        .arg(&current)
                        .arg(&mut halved)
                        .arg(&mut permuted)
                        .arg(&count)
                        .arg(&ntt.n)
                        .arg(&stage.degree)
                        .arg(&ntt.modulus)
                        .launch(config)?;
                }
            }
            // Preparing the current stage finishes all reads of the previous
            // output before key switching overwrites it. Thus two temporary
            // batches suffice, without an extra state buffer or final copy.
            self.key_switch.apply_checked(
                stage.key.as_view(),
                self.permuted.slice(..length),
                output.slice_mut(..),
                batch_size,
            )?;
            let halved = self.halved.slice(..length);
            // SAFETY: key switching and prepare wrote canonical coefficients
            // in two distinct equal-length batches on the same ordered stream.
            unsafe {
                ntt.stream
                    .launch_builder(&self.add)
                    .arg(&mut output)
                    .arg(&halved)
                    .arg(&count)
                    .arg(&ntt.modulus)
                    .launch(config)?;
            }
        }
        Ok(())
    }
}
