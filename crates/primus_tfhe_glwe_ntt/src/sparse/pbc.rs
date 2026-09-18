use rand::distr::{Distribution, Uniform};
use zeroize::Zeroizing;

use crate::SparseBootstrappingKeyError;

/// No assignment or no visited predecessor. Valid indices fit checked allocations.
pub(super) const EMPTY: usize = usize::MAX;
const MAX_ATTEMPTS: usize = 8;

/// Public mapping from buckets to input coefficient indices.
///
/// Each input index occurs in `copy_count` distinct buckets, including indices
/// whose secret coefficient is zero. No private matching information is retained.
pub(super) struct BucketMap {
    /// Bucket `j` occupies `input_indices[bucket_offsets[j]..bucket_offsets[j+1]]`.
    /// There are `bucket_count + 1` offsets; the last is `input_indices.len()`.
    pub(super) bucket_offsets: Vec<usize>,
    /// Original input coefficient indices, increasing within each bucket.
    pub(super) input_indices: Vec<usize>,
}

impl BucketMap {
    /// Samples a public bucket map and privately assigns every nonzero coefficient.
    ///
    /// `nonzero_indices` contains the increasing indices `i` where the binary
    /// input secret has `s[i] == 1`; its length is the Hamming weight. Each input
    /// index, including those outside this list, samples `copy_count` distinct
    /// buckets uniformly. Only the map is resampled on matching failure.
    ///
    /// Returns the public map and a private array indexed by bucket: each entry
    /// is the selected original input index, or `EMPTY` for an unoccupied bucket.
    /// Returns an error after eight failed maps; the input secret is unchanged.
    ///
    /// # Correctness
    ///
    /// Key generation has checked dimensions, allocation lengths and the actual
    /// binary secret: `copy_count >= 1`, `bucket_count >= max(copy_count, h)`,
    /// and the `h` distinct nonzero indices are all below `input_dimension`.
    pub(super) fn generate<R>(
        input_dimension: usize,
        copy_count: usize,
        bucket_count: usize,
        nonzero_indices: &[usize],
        rng: &mut R,
    ) -> Result<(Self, Zeroizing<Vec<usize>>), SparseBootstrappingKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let bucket_distribution = Uniform::new(0, bucket_count).expect("validated bucket count");
        Self::generate_with(
            input_dimension,
            copy_count,
            bucket_count,
            nonzero_indices,
            |candidate_buckets| {
                for input_buckets in candidate_buckets.chunks_exact_mut(copy_count) {
                    for copy_index in 0..copy_count {
                        loop {
                            let bucket_index = bucket_distribution.sample(rng);
                            if !input_buckets[..copy_index].contains(&bucket_index) {
                                input_buckets[copy_index] = bucket_index;
                                break;
                            }
                        }
                    }
                }
            },
        )
    }

    /// Tries up to eight sampled graphs using one matching workspace and fixed
    /// nonzero coefficient indices. Converts the successful graph to bucket-major
    /// storage only after all nonzero coefficients have been assigned.
    ///
    /// The sampler overwrites an input-major `[input_index][copy_index]` array:
    /// each row has `copy_count` distinct bucket IDs in `0..bucket_count`.
    /// Production sampling must be independent across inputs and attempts; the
    /// callback also lets tests supply graphs with known matching failures.
    /// Other input requirements and the returned private array match [`Self::generate`].
    fn generate_with(
        input_dimension: usize,
        copy_count: usize,
        bucket_count: usize,
        nonzero_indices: &[usize],
        mut sample: impl FnMut(&mut [usize]),
    ) -> Result<(Self, Zeroizing<Vec<usize>>), SparseBootstrappingKeyError> {
        let mut candidate_buckets = vec![0; input_dimension * copy_count];
        let mut matching = Matching::new(nonzero_indices.len(), bucket_count);
        for _ in 0..MAX_ATTEMPTS {
            sample(&mut candidate_buckets);
            if matching.assign(&candidate_buckets, copy_count, nonzero_indices) {
                let map = Self::from_input_buckets(&candidate_buckets, copy_count, bucket_count);
                return Ok((map, matching.selected_input_indices));
            }
        }
        Err(SparseBootstrappingKeyError::MatchingFailed)
    }

    /// Transposes input-major candidate buckets into the public bucket map.
    ///
    /// Count entries per bucket, take prefix sums, then fill each bucket while
    /// scanning input indices in order. This produces increasing bucket entries
    /// without sorting and never reads the secret or private matching.
    ///
    /// `candidate_buckets` contains complete rows of `copy_count` distinct valid
    /// bucket IDs. Counts and allocation lengths satisfy [`Self::generate`]'s
    /// checked bounds, so prefix sums fit and retain every input copy exactly once.
    fn from_input_buckets(
        candidate_buckets: &[usize],
        copy_count: usize,
        bucket_count: usize,
    ) -> Self {
        let mut bucket_offsets = vec![0; bucket_count + 1];
        for &bucket_index in candidate_buckets {
            bucket_offsets[bucket_index + 1] += 1;
        }
        for bucket_index in 0..bucket_count {
            bucket_offsets[bucket_index + 1] += bucket_offsets[bucket_index];
        }
        let mut write_offsets = bucket_offsets[..bucket_count].to_vec();
        let mut input_indices = vec![0; candidate_buckets.len()];
        for (input_index, input_buckets) in candidate_buckets.chunks_exact(copy_count).enumerate() {
            for &bucket_index in input_buckets {
                input_indices[write_offsets[bucket_index]] = input_index;
                write_offsets[bucket_index] += 1;
            }
        }
        Self {
            bucket_offsets,
            input_indices,
        }
    }
}

/// Private matching between nonzero input coefficients and candidate buckets.
///
/// Buckets store original input indices directly. Searching records a path of
/// buckets whose occupants can move to make room for a new input. All private
/// buffers are reused across attempts and erased on drop.
struct Matching {
    /// Bucket -> selected original input index, or `EMPTY` if unoccupied.
    selected_input_indices: Zeroizing<Vec<usize>>,
    /// Destination bucket -> bucket whose occupant can move into it.
    /// `EMPTY` means unvisited; a starting bucket points to itself and receives
    /// the new input when the path is applied.
    predecessor_buckets: Zeroizing<Vec<usize>>,
    /// Occupied buckets whose occupants' alternative candidates need visiting.
    pending_buckets: Zeroizing<Vec<usize>>,
}

impl Matching {
    /// Allocates an empty matching and reusable search buffers.
    /// At most `h` buckets are occupied, and each is queued at most once per
    /// search. The caller has checked lengths and uses the same weight and
    /// bucket range for every assignment with this workspace.
    fn new(hamming_weight: usize, bucket_count: usize) -> Self {
        Self {
            selected_input_indices: Zeroizing::new(vec![EMPTY; bucket_count]),
            predecessor_buckets: Zeroizing::new(vec![EMPTY; bucket_count]),
            pending_buckets: Zeroizing::new(Vec::with_capacity(hamming_weight)),
        }
    }

    /// Resets the matching and assigns every nonzero input to a distinct bucket.
    ///
    /// Candidate rows are indexed by original input coefficient; only rows named
    /// by `nonzero_indices` participate. Inputs satisfy [`BucketMap::generate`]'s
    /// bounds and match this workspace's dimensions. On failure, the partial
    /// matching cannot generate a key; the next call resets it before retrying.
    fn assign(
        &mut self,
        candidate_buckets: &[usize],
        copy_count: usize,
        nonzero_indices: &[usize],
    ) -> bool {
        self.selected_input_indices.fill(EMPTY);
        for &input_index in nonzero_indices {
            if !self.augment(input_index, candidate_buckets, copy_count) {
                return false;
            }
        }
        true
    }

    /// Adds one unassigned input, moving existing occupants only if necessary.
    ///
    /// First try an empty candidate. If all candidates are occupied, find a
    /// relocation path, then apply it backwards from its free end. Returns false
    /// only when no path exists; existing assignments remain unchanged.
    /// `input_index` is an unassigned original input index; candidate rows and
    /// existing assignments satisfy [`Self::assign`]'s contract.
    fn augment(
        &mut self,
        input_index: usize,
        candidate_buckets: &[usize],
        copy_count: usize,
    ) -> bool {
        let row_start = input_index * copy_count;
        let input_candidates = &candidate_buckets[row_start..row_start + copy_count];
        for &bucket in input_candidates {
            if self.selected_input_indices[bucket] == EMPTY {
                self.selected_input_indices[bucket] = input_index;
                return true;
            }
        }

        let Some(free_bucket) =
            self.find_relocation_path(input_candidates, candidate_buckets, copy_count)
        else {
            return false;
        };
        self.apply_relocation_path(input_index, free_bucket);
        true
    }

    /// Finds a path from an occupied candidate to a free bucket using BFS.
    ///
    /// For each occupied bucket, try moving its occupant to another candidate.
    /// Record `predecessor_buckets[destination] = source` when first reaching a
    /// bucket. The returned free bucket ends the path; assignments are untouched.
    /// Starting candidates must be distinct, occupied buckets from the current
    /// input's row. Other inputs inherit [`Self::augment`]'s contract.
    fn find_relocation_path(
        &mut self,
        input_candidates: &[usize],
        candidate_buckets: &[usize],
        copy_count: usize,
    ) -> Option<usize> {
        self.predecessor_buckets.fill(EMPTY);
        self.pending_buckets.clear();
        for &bucket in input_candidates {
            // A starting bucket has no predecessor: it will receive the new input.
            self.predecessor_buckets[bucket] = bucket;
            self.pending_buckets.push(bucket);
        }

        let mut queue_cursor = 0;
        while queue_cursor < self.pending_buckets.len() {
            let source_bucket = self.pending_buckets[queue_cursor];
            queue_cursor += 1;
            let occupant = self.selected_input_indices[source_bucket];
            let row_start = occupant * copy_count;
            for &destination in &candidate_buckets[row_start..row_start + copy_count] {
                if self.predecessor_buckets[destination] != EMPTY {
                    continue;
                }
                self.predecessor_buckets[destination] = source_bucket;
                if self.selected_input_indices[destination] == EMPTY {
                    return Some(destination);
                }
                self.pending_buckets.push(destination);
            }
        }
        None
    }

    /// Applies the path recorded by a successful [`Self::find_relocation_path`].
    ///
    /// For `A -> B -> C (free)`, move B's occupant to C, A's occupant to B, then
    /// put the new input in A. Each move vacates the source bucket; a predecessor
    /// pointing to itself marks the starting bucket. Assignments must be
    /// unchanged since the search.
    fn apply_relocation_path(&mut self, input_index: usize, mut free_bucket: usize) {
        loop {
            let source_bucket = self.predecessor_buckets[free_bucket];
            if source_bucket == free_bucket {
                self.selected_input_indices[free_bucket] = input_index;
                return;
            }
            self.selected_input_indices[free_bucket] = self.selected_input_indices[source_bucket];
            free_bucket = source_bucket;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_matching_agrees_with_brute_force() {
        let choices = [[0, 1], [0, 2], [0, 3], [1, 2], [1, 3], [2, 3]];
        let mut matching = Matching::new(3, 4);
        // All 6^3 graphs for three supported inputs, including cases requiring
        // displacement. Unsupported rows do not affect existence of a matching.
        for a in choices {
            for b in choices {
                for c in choices {
                    let candidate_buckets = [[0, 1], a, [0, 1], b, [0, 1], c].concat();
                    let possible = a.iter().any(|x| {
                        b.iter()
                            .any(|y| c.iter().any(|z| x != y && x != z && y != z))
                    });
                    assert_eq!(matching.assign(&candidate_buckets, 2, &[1, 3, 5]), possible);
                    if possible {
                        let mut selected_counts = [0; 6];
                        for (bucket, &input_index) in
                            matching.selected_input_indices.iter().enumerate()
                        {
                            if input_index == EMPTY {
                                continue;
                            }
                            selected_counts[input_index] += 1;
                            let row_start = input_index * 2;
                            assert!(candidate_buckets[row_start..row_start + 2].contains(&bucket));
                        }
                        assert_eq!(selected_counts, [0, 1, 0, 1, 0, 1]);
                    }
                }
            }
        }
    }

    #[test]
    fn retries_keep_the_support_and_stop_after_eight_failures() {
        let nonzero_indices = [0, 3, 6, 10];
        for success_at in [Some(2), Some(8), None] {
            let mut attempts = 0;
            let result =
                BucketMap::generate_with(16, 3, 8, &nonzero_indices, |candidate_buckets| {
                    attempts += 1;
                    for row in candidate_buckets.as_chunks_mut::<3>().0 {
                        row.copy_from_slice(&[0, 1, 2]);
                    }
                    if Some(attempts) == success_at {
                        candidate_buckets[30..33].copy_from_slice(&[3, 4, 5]);
                    }
                });
            assert_eq!(attempts, success_at.unwrap_or(8));
            if success_at.is_some() {
                let (map, selected_input_indices) = result.unwrap();
                let mut recovered: Vec<_> = selected_input_indices
                    .iter()
                    .copied()
                    .filter(|&i| i != EMPTY)
                    .collect();
                recovered.sort_unstable();
                assert_eq!(recovered, nonzero_indices);
                for (bucket_index, &input_index) in selected_input_indices.iter().enumerate() {
                    let entries = &map.input_indices
                        [map.bucket_offsets[bucket_index]..map.bucket_offsets[bucket_index + 1]];
                    assert!(entries.windows(2).all(|pair| pair[0] < pair[1]));
                    if input_index != EMPTY {
                        assert!(entries.contains(&input_index));
                    }
                }
                // Buckets 6 and 7 have no public entries or assigned nonzero coefficients.
                assert_eq!(&selected_input_indices[6..], &[EMPTY, EMPTY]);
                assert_eq!(&map.bucket_offsets[6..], &[48, 48, 48]);
            } else {
                assert!(matches!(
                    result,
                    Err(SparseBootstrappingKeyError::MatchingFailed)
                ));
            }
        }
    }
}
