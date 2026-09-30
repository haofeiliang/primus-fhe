//! Shared-input and streamed NTRU returns through bounded LWE key-switch tiles.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::lwe::{Lwe, LweIter, LweIterMut};
use primus_reduce::RingContext;

use super::NtruLweKeySwitchingKey;
use crate::NtruCiphertext;

// Match the LWE key-switch kernel's small tile without retaining all extracted
// samples. This bounds scratch independently of the caller's output count.
const RETURN_BATCH_SIZE: usize = 8;

impl<T: FheUint> NtruLweKeySwitchingKey<T> {
    /// Switches several coefficients of the same NTRU phase into separate LWEs.
    ///
    /// `indices` and `outputs` have equal counts; order and repeated indices are
    /// preserved. The iterator is cloned to validate all indices before writing.
    /// Empty batches leave output and scratch untouched. One output uses the
    /// direct scalar path. Larger batches convert the complete input from Q to q
    /// once, then extract and key-switch bounded tiles in reusable scratch.
    /// The converted coefficients remain live until every tile is returned.
    /// Results equal repeated [`Self::key_switch_at_to`] calls, without allocation.
    ///
    /// # Correctness
    /// The canonical coefficient, key and noise requirements of
    /// [`Self::key_switch_at_to`] apply. Conversion precedes extraction signs,
    /// including at rounding ties. Shared input noise remains correlated across
    /// outputs; batching introduces no new rounding or decomposition step.
    ///
    /// # Panics
    /// Panics before modifying output or scratch if input/workspace dimensions,
    /// output count or lengths, any index, or the target modulus is incompatible.
    /// An iterator that panics or changes its sequence when cloned may leave
    /// partial writes after validation.
    pub fn key_switch_many_at_to<M, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        indices: impl ExactSizeIterator<Item = usize> + Clone,
        outputs: &mut [Lwe<B>],
        modulus: M,
        workspace: &mut NtruLweKeySwitchingBatchWorkspace<T>,
    ) where
        M: RingContext<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.check_extraction(input.as_view(), indices.clone(), outputs.len());
        self.check_batch_outputs(outputs, modulus, workspace);
        let mut indices = indices;
        if outputs.is_empty() {
            return;
        }
        if outputs.len() == 1 {
            self.key_switch_coefficient(
                input.as_view(),
                indices.next().expect("NTRU extraction index missing"),
                outputs[0].as_mut_view(),
                modulus,
                workspace.extracted_mut(0),
            );
            return;
        }

        self.modulus_switch.switch_map(
            input
                .as_ref()
                .iter()
                .copied()
                .zip(workspace.converted.iter_mut()),
            |value, out| *out = value,
        );
        for outputs in outputs.chunks_mut(RETURN_BATCH_SIZE) {
            workspace.extract_converted_tile(&mut indices, outputs.len(), modulus);
            self.switch_extracted_tile(outputs, modulus, workspace);
        }
    }

    /// Key-switches the filled prefix of a reusable extracted-LWE tile.
    ///
    /// Reads the first `outputs.len()` samples prepared through
    /// [`Self::modulus_switch_extract_at_to`], preserving their order in outputs
    /// and leaving their slots intact for the caller to reuse. Outputs and switched
    /// scratch are overwritten without allocation. Empty batches do nothing; a
    /// singleton writes directly to the caller's LWE without a tile copy.
    ///
    /// # Correctness
    /// Every consumed sample must be an LWE under this key's signed f at q,
    /// satisfying [`LweKeySwitchingKey::key_switch_to`](primus_lwe::LweKeySwitchingKey::key_switch_to).
    /// Fill the entire consumed prefix for the current operation; the workspace
    /// tracks neither initialization nor key/modulus identity of stored samples.
    ///
    /// # Panics
    /// Panics before output/scratch writes if output count exceeds workspace
    /// capacity, workspace or output dimensions mismatch, or q is incompatible.
    pub fn key_switch_extracted_batch_to<M, B>(
        &self,
        outputs: &mut [Lwe<B>],
        modulus: M,
        workspace: &mut NtruLweKeySwitchingBatchWorkspace<T>,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        assert!(
            outputs.len() <= workspace.batch_capacity(),
            "NTRU return batch exceeds workspace capacity"
        );
        self.check_batch_outputs(outputs, modulus, workspace);
        self.switch_extracted_tile(outputs, modulus, workspace);
    }

    /// Validate the full extraction request before conversion or scratch writes.
    /// Consumes a cloned iterator so processing still starts at the original first index.
    fn check_extraction(
        &self,
        input: NtruCiphertext<&[T]>,
        mut indices: impl ExactSizeIterator<Item = usize>,
        output_count: usize,
    ) {
        let n = self.poly_length();
        assert_eq!(input.as_ref().len(), n, "NTRU input length mismatch");
        assert_eq!(
            indices.len(),
            output_count,
            "NTRU extraction count mismatch"
        );
        assert!(
            indices.all(|index| index < n),
            "NTRU extraction index is out of range"
        );
    }

    /// Shared-input and pre-extracted batches enforce the same target binding
    /// before touching any output. Their different count/index checks stay at
    /// the respective public boundary.
    fn check_batch_outputs<M, B>(
        &self,
        outputs: &[Lwe<B>],
        modulus: M,
        workspace: &NtruLweKeySwitchingBatchWorkspace<T>,
    ) where
        M: RingContext<T>,
        B: Data<Elem = T>,
    {
        let output_len = self.output_dimension() + 1;
        assert!(
            outputs
                .iter()
                .all(|output| output.as_ref().len() == output_len),
            "target LWE ciphertext length mismatch"
        );
        assert_eq!(
            workspace.poly_length(),
            self.poly_length(),
            "NTRU to LWE workspace length mismatch"
        );
        assert_eq!(
            workspace.output_dimension(),
            self.output_dimension(),
            "NTRU to LWE workspace output dimension mismatch"
        );
        assert_eq!(
            modulus.explicit_value(),
            self.basis().modulus(),
            "target LWE modulus mismatch"
        );
    }

    /// The public boundary validated this tile. The singleton path avoids an
    /// intermediate output copy; larger tiles reuse the existing LWE batch kernel.
    fn switch_extracted_tile<M, B>(
        &self,
        outputs: &mut [Lwe<B>],
        modulus: M,
        workspace: &mut NtruLweKeySwitchingBatchWorkspace<T>,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        let output_len = self.output_dimension() + 1;
        let (extracted, switched) = workspace.lwe_tiles_mut(outputs.len());
        match outputs {
            [] => {}
            [output] => self
                .key_switch
                .key_switch_to(&Lwe::new(extracted), output, modulus),
            _ => {
                self.key_switch
                    .key_switch_batch_to(extracted, switched, modulus);
                // The kernel writes a flat tile; callers own separate LWEs.
                for (output, sample) in outputs.iter_mut().zip(LweIter::new(switched, output_len)) {
                    output.as_mut().copy_from_slice(sample.as_ref());
                }
            }
        }
    }
}

/// Reusable scratch for returning coefficients of shared or streamed NTRU inputs.
///
/// Retains N converted coefficients and two tiles of eight LWEs: dimensions N
/// before key switching and `output_dimension` afterward. Storage is bounded
/// independently of the number of requested coefficients. Shared-input returns
/// reuse the converted polynomial; streamed returns fill extracted slots directly.
/// It holds ciphertext data only and need not be cleared between calls, but each
/// consumed extracted slot must be filled for the current operation.
pub struct NtruLweKeySwitchingBatchWorkspace<T: FheUint> {
    converted: Box<[T]>,
    extracted: Box<[T]>,
    switched: Box<[T]>,
    output_dimension: usize,
}

impl<T: FheUint> NtruLweKeySwitchingBatchWorkspace<T> {
    /// Fills one tile from the already rounded q-domain polynomial. The caller
    /// validated the complete index sequence and tile size; retaining `converted`
    /// across tiles avoids repeating Q→q. Extraction applies signs only afterward.
    fn extract_converted_tile<M: RingContext<T>>(
        &mut self,
        indices: &mut impl Iterator<Item = usize>,
        count: usize,
        modulus: M,
    ) {
        let sample_len = self.poly_length() + 1;
        let input = NtruCiphertext::new(&self.converted[..]);
        for mut sample in LweIterMut::new(&mut self.extracted[..count * sample_len], sample_len) {
            let index = indices.next().expect("NTRU extraction index missing");
            input.extract_lwe_at_to(index, &mut sample, modulus);
        }
    }

    /// Borrows matching prefixes of the intermediate and switched LWE tiles.
    /// Public boundaries already checked count <= capacity and key dimensions.
    fn lwe_tiles_mut(&mut self, count: usize) -> (&[T], &mut [T]) {
        let extracted_len = count * (self.poly_length() + 1);
        let switched_len = count * (self.output_dimension + 1);
        (
            &self.extracted[..extracted_len],
            &mut self.switched[..switched_len],
        )
    }

    /// Maximum number of intermediate LWEs retained for one return tile.
    #[must_use]
    pub const fn batch_capacity(&self) -> usize {
        RETURN_BATCH_SIZE
    }

    /// Borrows one N+1-element intermediate LWE slot, without allocating.
    /// Fill the whole sample at q before calling
    /// [`NtruLweKeySwitchingKey::key_switch_extracted_batch_to`].
    ///
    /// # Panics
    /// Panics if `slot` is outside [`Self::batch_capacity`].
    #[must_use]
    pub fn extracted_mut(&mut self, slot: usize) -> Lwe<&mut [T]> {
        let len = self.poly_length() + 1;
        LweIterMut::new(&mut self.extracted, len)
            .nth(slot)
            .expect("NTRU extracted LWE slot is out of range")
    }

    /// Allocates the converted polynomial and fixed input/output LWE tiles.
    ///
    /// # Panics
    /// Panics if either dimension is zero or a tile storage length overflows.
    #[must_use]
    pub fn new(poly_length: usize, output_dimension: usize) -> Self {
        assert!(poly_length > 0, "NTRU polynomial length must be nonzero");
        assert!(output_dimension > 0, "target LWE dimension must be nonzero");
        let tile_len = |dimension: usize| {
            dimension
                .checked_add(1)
                .and_then(|len| len.checked_mul(RETURN_BATCH_SIZE))
                .expect("NTRU to LWE batch workspace length overflow")
        };
        let extracted_len = tile_len(poly_length);
        let switched_len = tile_len(output_dimension);
        Self {
            converted: vec![T::ZERO; poly_length].into_boxed_slice(),
            extracted: vec![T::ZERO; extracted_len].into_boxed_slice(),
            switched: vec![T::ZERO; switched_len].into_boxed_slice(),
            output_dimension,
        }
    }

    /// Returns the input NTRU polynomial length supported by this workspace.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.converted.len()
    }

    /// Returns the target LWE dimension supported by this workspace.
    #[must_use]
    pub fn output_dimension(&self) -> usize {
        self.output_dimension
    }
}
