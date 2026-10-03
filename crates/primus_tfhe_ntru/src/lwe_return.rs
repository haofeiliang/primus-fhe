use primus_integer::FheUint;
use primus_ntru::{
    NtruCiphertext, NtruLweKeySwitchingBatchWorkspace, NtruLweKeySwitchingKey,
    NtruLweKeySwitchingWorkspace,
};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_tfhe::{Lwe, LweCiphertext};

/// Coefficient-domain NTRU→LWE returns, independent of blind rotation and NTT/FFT scratch.
///
/// Borrows the Q→q, f→s key and owns reusable scalar/batch buffers. It can be
/// composed with standalone one-hot CBS without retaining an ordinary PBS
/// evaluator. Single returns, shared-input prefixes and independent input streams
/// keep their different conversion schedules. All online methods allocate nothing.
/// Source secret identity, coefficient representation and noise are caller contracts.
pub struct LweReturnEvaluator<'a, T: FheUint, LM: RingContext<T>> {
    key: &'a NtruLweKeySwitchingKey<T>,
    modulus: LM,
    scalar: NtruLweKeySwitchingWorkspace<T>,
    batch: NtruLweKeySwitchingBatchWorkspace<T>,
    // None is idle; Some(k) owns exactly the current batch's valid prefix 0..k.
    // Old slot contents never become valid merely by starting another batch.
    prepared: Option<usize>,
}

impl<'a, T: FheUint, LM: RingContext<T>> LweReturnEvaluator<'a, T, LM> {
    /// Binds a return key to q and allocates one scalar buffer and bounded LWE tiles.
    ///
    /// # Panics
    /// Panics if q differs from the key's target modulus, its polynomial length is
    /// outside [`PolyLength`]'s supported range, or tile storage length overflows.
    #[must_use]
    pub fn new(key: &'a NtruLweKeySwitchingKey<T>, modulus: LM) -> Self {
        assert_eq!(
            modulus.explicit_value(),
            key.basis().modulus(),
            "target LWE modulus mismatch"
        );
        let poly_length = PolyLength::new(key.poly_length());
        Self {
            key,
            modulus,
            scalar: NtruLweKeySwitchingWorkspace::new(poly_length),
            batch: NtruLweKeySwitchingBatchWorkspace::new(poly_length, key.output_dimension()),
            prepared: None,
        }
    }

    /// Returns whether a stream owns the return buffers, including an empty active batch.
    #[must_use]
    pub fn is_batch_active(&self) -> bool {
        self.prepared.is_some()
    }

    fn check_idle(&self) {
        assert!(
            self.prepared.is_none(),
            "finish or discard the pending NTRU return batch first"
        );
    }

    /// Returns phase coefficient `index` at q under the independent LWE secret.
    ///
    /// # Correctness
    /// Inherits [`NtruLweKeySwitchingKey::key_switch_at_to`]'s canonical coefficient,
    /// source secret and noise requirements. Q→q precedes extraction signs.
    ///
    /// # Panics
    /// Rejects an active stream or invalid input/output lengths or index before writes.
    pub fn return_at_to(
        &mut self,
        input: NtruCiphertext<&[T]>,
        index: usize,
        mut output: Lwe<&mut [T]>,
    ) {
        self.check_idle();
        self.key
            .key_switch_at_to(&input, index, &mut output, self.modulus, &mut self.scalar);
    }

    /// Returns phase coefficients `0..outputs.len()` from one shared NTRU input.
    /// Larger requests reuse one Q→q conversion across bounded key-switch tiles;
    /// empty requests write nothing and a singleton uses the scalar path.
    ///
    /// # Correctness
    /// Inherits [`NtruLweKeySwitchingKey::key_switch_many_at_to`]'s key, canonical
    /// coefficient and noise requirements. Shared source noise remains correlated.
    ///
    /// # Panics
    /// Rejects an active stream or invalid input/output lengths or prefix indices
    /// before output/scratch writes.
    pub fn return_prefix_to(
        &mut self,
        input: NtruCiphertext<&[T]>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        self.check_idle();
        match outputs {
            [output] => {
                self.key
                    .key_switch_at_to(&input, 0, output, self.modulus, &mut self.scalar)
            }
            _ => self.key.key_switch_many_at_to(
                &input,
                0..outputs.len(),
                outputs,
                self.modulus,
                &mut self.batch,
            ),
        }
    }

    /// Maximum number of extracted LWEs retained in one streamed tile.
    #[must_use]
    pub fn batch_capacity(&self) -> usize {
        self.batch.batch_capacity()
    }

    /// Starts an empty stream, discarding any previous pending prefix without clearing buffers.
    /// BR/FFT and source buffers remain independently usable between appends.
    pub fn begin_batch(&mut self) {
        self.prepared = Some(0);
    }

    /// Converts/extracts one phase coefficient and appends it to the current prefix.
    /// No source borrow survives; the NTRU may be overwritten immediately afterward.
    ///
    /// # Correctness
    /// Inherits [`NtruLweKeySwitchingKey::modulus_switch_extract_at_to`]'s canonical
    /// coefficient, source secret and noise requirements. Conversion precedes signs.
    ///
    /// # Panics
    /// Rejects an inactive/full batch or invalid input length/index before writes.
    /// A rejected append does not advance the valid prefix.
    pub fn append_at(&mut self, input: NtruCiphertext<&[T]>, index: usize) {
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

    /// Returns the entire appended prefix in order, then ends the stream.
    /// Outputs must match its count exactly, including empty and short final tiles.
    /// Successful submission invalidates the prefix, preventing fresh/stale reads.
    ///
    /// # Correctness
    /// Inherits [`NtruLweKeySwitchingKey::key_switch_extracted_batch_to`]'s noise
    /// requirements for the intermediate LWEs prepared by [`Self::append_at`].
    ///
    /// # Panics
    /// Rejects an inactive batch, mismatched count or any wrong output dimension
    /// before output/scratch writes. Failed validation retains the prefix for retry
    /// or discard.
    pub fn return_batch_to(&mut self, outputs: &mut [LweCiphertext<T>]) {
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

    /// Cancels a stream without clearing buffers; does nothing when idle.
    /// Dropping this evaluator also drops pending samples.
    pub fn discard_batch(&mut self) {
        self.prepared = None;
    }
}
