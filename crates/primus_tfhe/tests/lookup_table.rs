//! Independent nearest-center oracles for ordinary, interleaved and odd-domain LUTs.

use std::cell::{Cell, RefCell};

use primus_encoding::RoundedCodec;
use primus_modulus::BarrettModulus;
use primus_tfhe::{LookupTableCompiler, LookupTableError, PolyLength};

const N: usize = 32;
const Q_IN: u32 = 97;
const Q_OUT: u32 = 257;

fn encode(message: u32, q: u32, t: u32) -> u32 {
    ((u64::from(message) * u64::from(q) + u64::from(t / 2)) / u64::from(t)) as u32 % q
}

fn center(message: u32, t: u32, period: usize) -> i32 {
    ((u64::from(encode(message, Q_IN, t)) * period as u64 + u64::from(Q_IN / 2)) / u64::from(Q_IN)
        % period as u64) as i32
}

fn negate(value: u32) -> u32 {
    (Q_OUT - value) % Q_OUT
}

/// Search all declared centers; ties select the larger position. This avoids
/// reproducing the compiler's interval endpoints or fill loops.
fn nearest(centers: &[(i32, u32)], position: usize) -> u32 {
    centers
        .iter()
        .min_by_key(|&&(x, _)| ((x - position as i32).abs(), -x))
        .unwrap()
        .1
}

#[test]
fn front_half_and_interleaved_intervals_match_nearest_centers() {
    let input = RoundedCodec::new(8, BarrettModulus::new(Q_IN));
    // Different input/output message AND ciphertext moduli.
    let output = RoundedCodec::new(5, BarrettModulus::new(Q_OUT));
    let compiler = LookupTableCompiler::try_new(
        PolyLength::new(N),
        &input,
        BarrettModulus::new(Q_OUT),
        &output,
    )
    .unwrap();
    for count in [1usize, 3] {
        let calls = RefCell::new(Vec::new());
        let function = |m: usize, j: usize| {
            calls.borrow_mut().push((m, j));
            ((2 * m + j + 1) % 5) as u32
        };
        let coefficients = if count == 1 {
            compiler
                .compile_fn(|m| function(m, 0))
                .unwrap()
                .polynomial()
                .as_ref()
                .to_vec()
        } else {
            compiler
                .compile_interleaved_fn(count, function)
                .unwrap()
                .polynomial()
                .as_ref()
                .to_vec()
        };
        assert_eq!(
            *calls.borrow(),
            (0..4)
                .flat_map(|m| (0..count).map(move |j| (m, j)))
                .collect::<Vec<_>>()
        );
        let stride = count.next_power_of_two();
        for lane in 0..stride {
            let value = |m| {
                if lane < count {
                    encode(((2 * m + lane + 1) % 5) as u32, Q_OUT, 5)
                } else {
                    0
                }
            };
            let mut centers: Vec<_> = (0..4)
                .map(|m| (center(m, 8, 2 * N / stride), value(m as usize)))
                .collect();
            centers.push(((N / stride) as i32, negate(value(0))));
            for position in 0..N / stride {
                assert_eq!(
                    coefficients[position * stride + lane],
                    nearest(&centers, position)
                );
            }
        }
    }
}

#[test]
fn odd_full_domain_folds_signs_and_signed_seam() {
    let input = RoundedCodec::new(5, BarrettModulus::new(Q_IN));
    let output = RoundedCodec::new(8, BarrettModulus::new(Q_OUT));
    let compiler = LookupTableCompiler::try_new(
        PolyLength::new(N),
        &input,
        BarrettModulus::new(Q_OUT),
        &output,
    )
    .unwrap();
    let table = compiler
        .compile_odd_full_domain_fn(|m| ((m * m + 1) % 8) as u32)
        .unwrap();
    let mut centers = Vec::new();
    for m in 0..5 {
        let exponent = center(m, 5, 2 * N);
        let value = encode((m * m + 1) % 8, Q_OUT, 8);
        // Negacyclic extension supplies signed copies on both sides of [0,N).
        for turn in -2i32..=1 {
            centers.push((
                exponent + turn * N as i32,
                if turn % 2 == 0 { value } else { negate(value) },
            ));
        }
    }
    for (position, &value) in table.polynomial().as_ref().iter().enumerate() {
        assert_eq!(value, nearest(&centers, position));
    }
}

#[test]
fn compiler_rejects_mismatched_domains_before_callback() {
    let q = BarrettModulus::new(Q_IN);
    let input = RoundedCodec::new(16, q);
    let output = RoundedCodec::new(8, BarrettModulus::new(Q_OUT));
    assert!(matches!(
        LookupTableCompiler::try_new(PolyLength::new(N), &input, q, &output),
        Err(LookupTableError::OutputModulusMismatch)
    ));
    let compiler = LookupTableCompiler::try_new(
        PolyLength::new(N),
        &input,
        BarrettModulus::new(Q_OUT),
        &output,
    )
    .unwrap();
    let calls = Cell::new(0);
    let result = compiler.compile_interleaved_fn(5, |_, _| {
        calls.set(calls.get() + 1);
        0
    });
    assert!(matches!(
        result,
        Err(LookupTableError::PlaintextDomainTooLarge { .. })
    ));
    assert_eq!(calls.get(), 0);
    assert!(matches!(
        compiler.compile_slice(&[8]),
        Err(LookupTableError::DomainLengthMismatch { .. })
    ));
    assert!(matches!(
        compiler.compile_fn(|m| if m == 2 { 8 } else { 0 }),
        Err(LookupTableError::OutputOutOfRange { input: 2 })
    ));
}
