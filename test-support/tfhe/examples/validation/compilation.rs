//! Public LUT-construction checks without keys, encryption or transform tables.
//! An explicit power-of-two modulus here checks the compiler, not FFT support.

use primus_integer::FheUint;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use primus_tfhe::{InterleavedLookupTable, LookupTable};
use primus_tfhe_test_support::parameters::ntt_modulus;

/// Checks both coefficient widths across native, power-of-two and NTT moduli.
pub fn validate() {
    word::<u32>();
    word::<u64>();
}

/// Selects the three modulus representations for one coefficient width.
fn word<T: FheUint>() {
    compile::<T, _>(NativeModulus::new());
    compile::<T, _>(PowOf2Modulus::new(T::ONE << 24u32));
    compile::<T, _>(ntt_modulus());
}

/// Checks odd/even domains, padded output counts and representative ring lengths.
/// This checks parameter acceptance; polynomial-content oracles remain in
/// primus_tfhe's small-parameter tests.
fn compile<T, M>(modulus: M)
where
    T: FheUint,
    M: RingContext<T>,
{
    for n in [1024, 2048] {
        for (t, count) in [(4usize, 4), (16, 1), (16, 3), (16, 4), (16, 16), (255, 4)] {
            let domain = t.div_ceil(2);
            let t = T::as_from(t);
            if count == 1 {
                LookupTable::try_new(domain, n, t, modulus, modulus, |m| Ok(T::as_from(13 * m)))
                    .unwrap();
            } else {
                InterleavedLookupTable::try_new(domain, n, count, t, modulus, modulus, |m, i| {
                    Ok(T::as_from(13 * m + i))
                })
                .unwrap();
            }
        }
    }
}
