//! Shared LUT compiler boundaries, raw scales, and rotation layout.
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_tfhe::{
    LookupTableError, compile_encoded_lookup_table, compile_encoded_many_lookup_table,
};

#[test]
fn raw_compilation_validates_layout_encoding_and_canonical_outputs() {
    let modulus = BarrettModulus::new(97u32);
    for (domain, n, t, q, expected) in [
        (
            0,
            64,
            4,
            Some(97),
            LookupTableError::InvalidInputDomain {
                domain_len: 0,
                max_domain_len: 2,
            },
        ),
        (
            3,
            64,
            4,
            Some(97),
            LookupTableError::InvalidInputDomain {
                domain_len: 3,
                max_domain_len: 2,
            },
        ),
        (2, 0, 4, Some(97), LookupTableError::InvalidPolynomialLength),
        (2, 3, 4, Some(97), LookupTableError::InvalidPolynomialLength),
        (
            2,
            usize::MAX / 2 + 1,
            4,
            Some(97),
            LookupTableError::InvalidPolynomialLength,
        ),
        (2, 64, 1, Some(97), LookupTableError::InvalidInputEncoding),
        (2, 64, 4, Some(4), LookupTableError::InvalidInputEncoding),
    ] {
        let error = compile_encoded_lookup_table(domain, n, t, q, modulus, |_| {
            panic!("invalid compilation arguments must precede output generation")
        })
        .unwrap_err();
        assert_eq!(error, expected);
    }
    assert_eq!(
        compile_encoded_lookup_table(2, 64, 4, Some(97), modulus, |input| Ok(if input == 0 {
            1
        } else {
            97
        }))
        .unwrap_err(),
        LookupTableError::EncodedOutputOutOfRange { input: 1 },
    );
    for (count, expected) in [
        (
            0,
            LookupTableError::OutputCountMustBePowerOfTwo { output_count: 0 },
        ),
        (
            3,
            LookupTableError::OutputCountMustBePowerOfTwo { output_count: 3 },
        ),
        (
            128,
            LookupTableError::OutputCountTooLarge {
                output_count: 128,
                poly_length: 64,
            },
        ),
        (
            64,
            LookupTableError::PlaintextDomainTooLarge {
                domain_len: 2,
                rotation_domain_len: 1,
            },
        ),
    ] {
        assert_eq!(
            compile_encoded_many_lookup_table(2, 64, count, 4, Some(97), modulus, |_, _| Ok(0))
                .unwrap_err(),
            expected
        );
    }
}

#[test]
fn interleaved_residue_classes_preserve_independent_raw_scales() {
    // The two outputs deliberately do not use the ordinary q/t scale.
    // This is needed by Boolean and gadget-scaled circuit bootstrapping.
    let raw = |input: usize, output| {
        Ok(if output == 0 {
            input as u32
        } else {
            (1 << 29) + input as u32
        })
    };
    let many =
        compile_encoded_many_lookup_table(2, 64, 2, 4, None, NativeModulus::new(), raw).unwrap();
    assert!(many.is_compatible(64, 4, None, None));
    for output in 0..2 {
        let single = compile_encoded_lookup_table(2, 32, 4, None, NativeModulus::new(), |input| {
            raw(input, output)
        })
        .unwrap();
        for (index, &value) in single.polynomial().as_ref().iter().enumerate() {
            assert_eq!(many.polynomial().as_ref()[index * 2 + output], value);
        }
    }
}

#[test]
fn odd_and_even_domains_preserve_both_sides_of_each_rotation_center() {
    use primus_encoding::{PlaintextEmbedding, RoundedCodec};
    const Q: u32 = 97;
    const N: usize = 64;
    for t in [3u32, 4, 5] {
        for count in [1, 2, 4] {
            let domain_len = t.div_ceil(2) as usize;
            let table = compile_encoded_many_lookup_table(
                domain_len,
                N,
                count,
                t,
                Some(Q),
                BarrettModulus::new(Q),
                |input, output| Ok((1 + input * count + output) as u32),
            )
            .unwrap();
            let codec = RoundedCodec::new(t, Some(Q));
            let two_virtual_n = 2 * N / count;
            for input in 0..domain_len {
                let encoded = codec.encode_value(input as u32, PlaintextEmbedding::Unsigned);
                // Independent integer rounding oracle for the windowed exponent.
                let center = (encoded as usize * two_virtual_n + Q as usize / 2) / Q as usize;
                for offset in [-1isize, 0, 1] {
                    let rotation = center.wrapping_add_signed(offset) & (two_virtual_n - 1);
                    for output in 0..count {
                        let index = rotation * count + output;
                        // Coefficient `output` of X^(-rotation*count) * LUT.
                        let coefficient = table.polynomial().as_ref()[index % N];
                        let actual = if index < N || coefficient == 0 {
                            coefficient
                        } else {
                            Q - coefficient
                        };
                        assert_eq!(
                            actual,
                            (1 + input * count + output) as u32,
                            "t={t}, count={count}, input={input}, offset={offset}"
                        );
                    }
                }
            }
        }
    }
}
