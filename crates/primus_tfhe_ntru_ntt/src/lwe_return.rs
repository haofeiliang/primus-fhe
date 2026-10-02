use primus_integer::FheUint;
use primus_ntru::{
    NtruCiphertext, NtruLweKeySwitchingBatchWorkspace, NtruLweKeySwitchingKey,
    NtruLweKeySwitchingWorkspace,
};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_tfhe::LweCiphertext;

/// Bound coefficient-domain return resources, independent of BR and transform scratch.
/// The owning evaluator has already checked the key's Q, q and dimensions.
pub(crate) struct LweReturnEngine<'a, T: FheUint, LM: RingContext<T>> {
    key: &'a NtruLweKeySwitchingKey<T>,
    modulus: LM,
    scalar: NtruLweKeySwitchingWorkspace<T>,
    batch: NtruLweKeySwitchingBatchWorkspace<T>,
    // None is idle; Some(k) owns exactly the current batch's valid prefix 0..k.
    // Old slot contents never become valid merely by starting another batch.
    prepared: Option<usize>,
}

impl<'a, T: FheUint, LM: RingContext<T>> LweReturnEngine<'a, T, LM> {
    #[must_use]
    pub(crate) fn new(
        key: &'a NtruLweKeySwitchingKey<T>,
        poly_length: PolyLength,
        modulus: LM,
    ) -> Self {
        Self {
            key,
            modulus,
            scalar: NtruLweKeySwitchingWorkspace::new(poly_length),
            batch: NtruLweKeySwitchingBatchWorkspace::new(poly_length, key.output_dimension()),
            prepared: None,
        }
    }

    /// Ordinary PBS must not consume scratch owned by an unfinished streamed batch.
    pub(crate) fn check_idle(&self) {
        assert!(
            self.prepared.is_none(),
            "finish or discard the pending NTRU return batch first"
        );
    }

    /// Single returns fuse Q→q with extraction; the owning boundary established idle state.
    pub(crate) fn return_at_to(
        &mut self,
        input: NtruCiphertext<&[T]>,
        index: usize,
        output: &mut LweCiphertext<T>,
    ) {
        self.key
            .key_switch_at_to(&input, index, output, self.modulus, &mut self.scalar);
    }

    /// Shared-input returns retain one converted polynomial across all extraction tiles.
    /// This is deliberately separate from streams, which round each source independently.
    pub(crate) fn return_prefix_to(
        &mut self,
        input: NtruCiphertext<&[T]>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        match outputs {
            [output] => self.return_at_to(input, 0, output),
            _ => self.key.key_switch_many_at_to(
                &input,
                0..outputs.len(),
                outputs,
                self.modulus,
                &mut self.batch,
            ),
        }
    }

    #[must_use]
    pub(crate) fn batch_capacity(&self) -> usize {
        self.batch.batch_capacity()
    }

    /// Starting/restarting discards the previous prefix without clearing ciphertext storage.
    pub(crate) fn begin_batch(&mut self) {
        self.prepared = Some(0);
    }

    /// Append only after successful extraction. No source borrow survives this call,
    /// so BR/FFT and the product buffers can be reused while the prefix stays live.
    pub(crate) fn append_at(&mut self, input: NtruCiphertext<&[T]>, index: usize) {
        let count = self
            .prepared
            .expect("begin an NTRU return batch before appending");
        assert!(
            count < self.batch_capacity(),
            "NTRU return batch exceeds workspace capacity"
        );
        self.key.modulus_switch_extract_at_to(
            input,
            index,
            self.batch.extracted_slot_mut(count),
            self.modulus,
        );
        self.prepared = Some(count + 1);
    }

    /// Submit exactly the valid prefix. Count and all output dimensions are checked
    /// before writes; failed validation retains the prefix so callers can retry or discard.
    /// Successful submission invalidates it, preventing fresh/stale slot consumption.
    pub(crate) fn return_batch_to(&mut self, outputs: &mut [LweCiphertext<T>]) {
        let count = self
            .prepared
            .expect("begin an NTRU return batch before submitting");
        assert_eq!(
            outputs.len(),
            count,
            "NTRU return output count differs from the prepared prefix"
        );
        self.key
            .key_switch_extracted_batch_to(outputs, self.modulus, &mut self.batch);
        self.discard_batch();
    }

    pub(crate) fn discard_batch(&mut self) {
        self.prepared = None;
    }
}
