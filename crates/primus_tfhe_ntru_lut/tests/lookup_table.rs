use primus_decompose::DecompositionLevelCount;
use primus_encoding::RoundedCodec;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_tfhe_ntru_lut::{
    ChunkFormat, HighPrecisionLookupTable, LookupTableConfig, LookupTableError, LookupTableStats,
    LookupWorkspaceEstimate,
};

// Verifies logical indexing, encoding and sharing against an integer oracle.
// The u128 modulus also represents the native u64 modulus 2^64 exactly.
fn geometry<M: RingContext<u64>>(modulus: M, q: u128) {
    let input_codec = RoundedCodec::new(8, PowOf2Modulus::new(1 << 24));
    for coefficient_chunk_count in 0..=3 {
        let config = LookupTableConfig {
            input_chunk_count: 3,
            output_chunk_count: 2,
            coefficient_chunk_count,
        };
        let mut calls = Vec::new();
        let lut = HighPrecisionLookupTable::try_new(
            PolyLength::new(64),
            modulus,
            &input_codec,
            config,
            |x, output| {
                calls.push((x, output));
                ((x * 3 + x / 4 + 5) >> (2 * output)) as u64 % 4
            },
        )
        .unwrap();
        assert_eq!(lut.config(), config);
        assert_eq!(lut.chunk_bits(), 2);
        assert_eq!(lut.chunk_format(), ChunkFormat::new(2));
        assert_eq!(lut.input_value_count(), 64);
        assert_eq!(
            lut.entries_per_polynomial(),
            4usize.pow(coefficient_chunk_count as u32)
        );
        assert_eq!(
            lut.polynomials_per_output(),
            64 / lut.entries_per_polynomial()
        );
        assert_eq!(
            calls,
            (0..2)
                .flat_map(|o| (0..64).map(move |x| (x, o)))
                .collect::<Vec<_>>()
        );
        let mut unique = Vec::new();
        for output in 0..2 {
            for prefix in 0..lut.polynomials_per_output() {
                let polynomial = lut.polynomial(output, prefix);
                if !unique
                    .iter()
                    .any(|p: &Vec<u64>| p.as_slice() == polynomial.as_ref())
                {
                    unique.push(polynomial.as_ref().to_vec());
                }
                for index in 0..64 {
                    let expected = if index < lut.entries_per_polynomial() {
                        let x = prefix * lut.entries_per_polynomial() + index;
                        let digit = ((3 * x + x / 4 + 5) >> (2 * output)) % 4;
                        ((q * digit as u128 + 4) / 8) as u64
                    } else {
                        0
                    };
                    assert_eq!(polynomial.as_ref()[index], expected);
                }
            }
        }
        assert_eq!(lut.unique_polynomial_count(), unique.len());
        assert!(std::panic::catch_unwind(|| lut.polynomial(2, 0)).is_err());
        assert!(
            std::panic::catch_unwind(|| lut.polynomial(0, lut.polynomials_per_output())).is_err()
        );
        assert!(lut.is_compatible(
            PolyLength::new(64),
            modulus,
            input_codec.ciphertext_modulus()
        ));
        // Compatibility checks domains at binding, independently of key/noise parameters.
        assert!(!lut.is_compatible(
            PolyLength::new(32),
            modulus,
            input_codec.ciphertext_modulus()
        ));
        assert!(!lut.is_compatible(PolyLength::new(64), modulus, PowOf2Modulus::new(1 << 23)));
    }
    // An output wider than u64 remains a sequence of independently compiled
    // digits; only optional word conversion has a machine-word capacity limit.
    let wide = HighPrecisionLookupTable::try_new(
        PolyLength::new(32),
        modulus,
        &input_codec,
        LookupTableConfig {
            input_chunk_count: 1,
            output_chunk_count: 33,
            coefficient_chunk_count: 0,
        },
        |x, output| if output == 32 { x as u64 } else { 0 },
    )
    .unwrap();
    assert_eq!(wide.stats().input_bits, 2);
    assert_eq!(wide.stats().output_bits, 66);
    for x in 0..4 {
        assert_eq!(
            wide.polynomial(32, x).as_ref()[0],
            ((q * x as u128 + 4) / 8) as u64
        );
    }
}

// Covers every legal digit with direct encoding, the largest precomputed radix,
// and the first radix above the temporary-cache cap. Check the zero tail too.
fn chunk_encoding_boundaries<M: RingContext<u64>>(modulus: M, q: u128) {
    for (radix, output_chunk_count) in [(4, 1), (256, 2), (512, 2)] {
        let input_codec = RoundedCodec::new(2 * radix as u64, PowOf2Modulus::new(1 << 24));
        let lut = HighPrecisionLookupTable::try_new(
            PolyLength::new(64),
            modulus,
            &input_codec,
            LookupTableConfig {
                input_chunk_count: 1,
                output_chunk_count,
                coefficient_chunk_count: 0,
            },
            |x, output| ((x + output) % radix) as u64,
        )
        .unwrap();
        for output in 0..output_chunk_count {
            for x in 0..radix {
                let polynomial = lut.polynomial(output, x);
                let digit = (x + output) % radix;
                let expected = (q * digit as u128 + radix as u128) / (2 * radix as u128);
                assert_eq!(polynomial.as_ref()[0], expected as u64);
                assert!(polynomial.as_ref()[1..].iter().all(|&value| value == 0));
            }
        }
    }
}

// Exercises prime and native moduli across every coefficient/table partition.
#[test]
fn table_partition_and_chunk_encoding_match_integer_oracle() {
    geometry(BarrettModulus::new(65_537u64), 65_537);
    geometry(NativeModulus::new(), 1u128 << 64);
    chunk_encoding_boundaries(BarrettModulus::new(65_537u64), 65_537);
    chunk_encoding_boundaries(NativeModulus::new(), 1u128 << 64);
}

// Invalid geometry must fail before callbacks; invalid digits report their exact pair.
#[test]
fn compilation_rejects_invalid_domains_before_callbacks() {
    let modulus = BarrettModulus::new(65_537u64);
    let input_codec = RoundedCodec::new(4, PowOf2Modulus::new(1 << 24));
    for (input_chunk_count, output_chunk_count, coefficient_chunk_count, expected) in [
        (0, 1, 0, LookupTableError::EmptyChunks),
        (1, 0, 0, LookupTableError::EmptyChunks),
        (1, 1, 2, LookupTableError::InvalidCoefficientChunkCount),
        (7, 1, 7, LookupTableError::InsufficientCapacity),
        (
            usize::BITS as usize,
            1,
            0,
            LookupTableError::StorageSizeOverflow,
        ),
        (
            usize::BITS as usize - 2,
            1,
            0,
            LookupTableError::StorageSizeOverflow,
        ),
        (1, usize::MAX, 0, LookupTableError::StorageSizeOverflow),
    ] {
        let result = HighPrecisionLookupTable::try_new(
            PolyLength::new(64),
            modulus,
            &input_codec,
            LookupTableConfig {
                input_chunk_count,
                output_chunk_count,
                coefficient_chunk_count,
            },
            |_, _| panic!("invalid geometry must not invoke the callback"),
        );
        assert_eq!(result.err(), Some(expected));
    }
    let config = LookupTableConfig {
        input_chunk_count: 2,
        output_chunk_count: 2,
        coefficient_chunk_count: 1,
    };
    let mut calls = Vec::new();
    let result = HighPrecisionLookupTable::try_new(
        PolyLength::new(64),
        modulus,
        &input_codec,
        config,
        |x, output| {
            calls.push((x, output));
            if (x, output) == (1, 1) { u64::MAX } else { 0 }
        },
    );
    assert_eq!(
        result.err(),
        Some(LookupTableError::OutputChunkOutOfRange {
            input: 1,
            output: 1
        })
    );
    assert_eq!(calls, [(0, 0), (1, 0), (2, 0), (3, 0), (0, 1), (1, 1)]);
    for t in [2, 6] {
        let modulus = BarrettModulus::new(65_537u64);
        let input_codec = RoundedCodec::new(t, PowOf2Modulus::new(1 << 24));
        assert_eq!(
            HighPrecisionLookupTable::try_new(
                PolyLength::new(64),
                modulus,
                &input_codec,
                config,
                |_, _| panic!()
            )
            .err(),
            Some(LookupTableError::InvalidPlaintextModulus)
        );
    }
    let small_ring = BarrettModulus::new(257u64);
    let too_large = RoundedCodec::new(512, PowOf2Modulus::new(1 << 24));
    let config = LookupTableConfig {
        input_chunk_count: 1,
        output_chunk_count: 1,
        coefficient_chunk_count: 0,
    };
    assert!(matches!(
        HighPrecisionLookupTable::try_new(
            PolyLength::new(64),
            small_ring,
            &too_large,
            config,
            |_, _| panic!()
        ),
        Err(LookupTableError::OutputEncoding(_))
    ));
}

// Public choices lift with their selectors; only explicit pruned leaves need NLEV[1].
#[test]
fn public_lift_requirement_follows_pruned_choices() {
    let modulus = NativeModulus::new();
    let codec = RoundedCodec::new(4, PowOf2Modulus::new(1 << 24));
    for (d, mapping, needs_lift) in [(1, 0, false), (1, 1, true), (1, 2, true), (3, 0, true)] {
        let table = HighPrecisionLookupTable::try_new(
            PolyLength::new(64),
            modulus,
            &codec,
            LookupTableConfig {
                input_chunk_count: 3,
                output_chunk_count: 1,
                coefficient_chunk_count: d,
            },
            |x, _| match mapping {
                // Four different two-coefficient polynomials: every choice survives.
                0 => ((x / 2) >> (x % 2) & 1) as u64,
                // One high branch is public zero, the other depends on chunk one.
                1 => {
                    if x < 4 {
                        0
                    } else {
                        (x >> 1 & 1) as u64
                    }
                }
                // Both high chunks are pruned; the root remains a public polynomial.
                _ => (x & 1) as u64,
            },
        )
        .unwrap();
        assert_eq!(
            table.needs_public_lift(),
            needs_lift,
            "d={d}, mapping={mapping}"
        );
    }
}

// Inspect costs without TFHE parameters or a backend. Expected bytes count the
// actual retained scalar/complex buffers, excluding the documented nested workspaces.
#[test]
fn costs_follow_pruning_and_storage_representation() {
    let poly_length = PolyLength::new(32);
    let modulus = NativeModulus::<u64>::new();
    let codec = RoundedCodec::new(4, PowOf2Modulus::new(1 << 24));
    let levels = DecompositionLevelCount::new(2);
    for (config, expected, bytes) in [
        (
            // Repeated outputs and both high chunks collapse to one public root.
            LookupTableConfig {
                input_chunk_count: 3,
                output_chunk_count: 2,
                coefficient_chunk_count: 1,
            },
            LookupTableStats {
                input_bits: 3,
                output_bits: 2,
                logical_polynomial_count: 8,
                unique_polynomial_count: 1,
                one_hot_chunk_count: 1,
                nlev_selector_count: 0,
                ngsw_selector_count: 1,
                selection_node_count: 1,
                public_lift_count: 1,
                result_slot_count: 1,
            },
            // NTT: 64 controls + 64 selector scratch + 32 factors + 32 slots + 64 work.
            // FFT: 112 complex (including 32 gadget-one) + 96 coefficient elements.
            LookupWorkspaceEstimate {
                ntt_bytes: 256 * 8,
                fourier_bytes: 112 * 16 + 96 * 8,
            },
        ),
        (
            // No rotation: one public choice retains both NLEV selectors.
            LookupTableConfig {
                input_chunk_count: 1,
                output_chunk_count: 1,
                coefficient_chunk_count: 0,
            },
            LookupTableStats {
                input_bits: 1,
                output_bits: 1,
                logical_polynomial_count: 2,
                unique_polynomial_count: 2,
                one_hot_chunk_count: 1,
                nlev_selector_count: 2,
                ngsw_selector_count: 0,
                selection_node_count: 1,
                public_lift_count: 0,
                result_slot_count: 1,
            },
            // NTT: 128 selectors + 32 slots + 64 work. FFT additionally needs
            // 128 coefficient elements for converting the public-selector batch.
            LookupWorkspaceEstimate {
                ntt_bytes: 224 * 8,
                fourier_bytes: 64 * 16 + 224 * 8,
            },
        ),
    ] {
        let table =
            HighPrecisionLookupTable::try_new(poly_length, modulus, &codec, config, |x, _| {
                (x & 1) as u64
            })
            .unwrap();
        assert_eq!(table.stats(), expected);
        assert_eq!(table.needs_public_lift(), expected.public_lift_count > 0);
        assert_eq!(table.estimate_workspace(levels).unwrap(), bytes);
        assert_eq!(
            table.estimate_workspace(DecompositionLevelCount::new(usize::MAX)),
            Err(LookupTableError::StorageSizeOverflow),
        );
    }
}
