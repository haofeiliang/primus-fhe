use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNtruCiphertext, FourierNtruEncryptContext, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey, FourierNtruTraceContext, FourierNtruTraceKey, NlevParameters,
    NtruCiphertext, NtruParameters, NtruSecretKey, NttNtruCiphertext, NttNtruGadgetEncryptContext,
    NttNtruSecretKey, NttNtruTraceContext, NttNtruTraceKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};

const N: usize = 32;
const Q: u64 = 1_125_899_906_826_241;

fn secret() -> NtruSecretKey<u64> {
    let mut f = vec![0; N];
    f[0] = 1;
    f[1] = 1;
    f[3] = -1;
    NtruSecretKey::new(f, SecretKeyDistr::SparseTernary)
}

// Independent schoolbook multiplication, including every non-target phase coefficient.
fn phase(cipher: &[u64], secret: &[i64], q: u128) -> Vec<u64> {
    let mut phase = vec![0u64; N];
    for (i, &c) in cipher.iter().enumerate() {
        for (j, &f) in secret.iter().enumerate() {
            let negative = (i + j >= N) ^ (f < 0);
            let product = u128::from(c) * u128::from(f.unsigned_abs()) % q;
            let term = if negative { (q - product) % q } else { product };
            let index = (i + j) % N;
            phase[index] = ((u128::from(phase[index]) + term) % q) as u64;
        }
    }
    phase
}

fn assert_phase(cipher: &[u64], expected: &[u64], secret: &[i64], q: u128) {
    for (i, (actual, &expected)) in phase(cipher, secret, q)
        .into_iter()
        .zip(expected)
        .enumerate()
    {
        let delta = (u128::from(actual) + q - u128::from(expected)) % q;
        // A fixed functional-fixture tolerance, not a security/noise estimate.
        // It is small relative to the 50/64-bit moduli and rejects wrong scales,
        // slot permutations and modular half-modulus errors.
        assert!(
            delta.min(q - delta) < (1 << 28),
            "phase[{i}]={actual}, expected {expected}, distance {}",
            delta.min(q - delta)
        );
    }
}

fn message(q: u128) -> Vec<u64> {
    (0..N)
        .map(|i| ((3 * i + 1) % 16) as u128 * (q / 64))
        .map(|x| x as u64)
        .collect()
}

enum Operation<'a> {
    Trace(usize),
    Reverse(usize),
    Project(&'a [usize]),
    ProjectPrefix(usize),
    Expand(usize),
}

fn check_operations(
    input: &NtruCiphertext<Vec<u64>>,
    message: &[u64],
    secret: &[i64],
    q: u128,
    mut run: impl FnMut(Operation<'_>, &mut [u64]),
) {
    let mut output = vec![7u64; N];
    for r in [1, 4, N] {
        let d = N / r;
        let retained: Vec<u64> = message
            .iter()
            .enumerate()
            .map(|(i, &value)| if i % d == 0 { value } else { 0 })
            .collect();
        run(Operation::Reverse(r), &mut output);
        assert_phase(&output, &retained, secret, q);
        if r == N {
            assert_eq!(output, input.as_ref());
        }
        run(Operation::Trace(r), &mut output);
        let scaled: Vec<u64> = retained
            .iter()
            .map(|&value| (u128::from(value) * d as u128 % q) as u64)
            .collect();
        assert_phase(&output, &scaled, secret, q);
    }
    for indices in [&[N - 1, 0, 7, 7][..], &[3][..], &[][..]] {
        output.resize(indices.len() * N, 7);
        run(Operation::Project(indices), &mut output);
        for (cipher, &index) in output.as_chunks::<N>().0.iter().zip(indices) {
            let mut expected = vec![0; N];
            expected[0] = message[index];
            assert_phase(cipher, &expected, secret, q);
        }
    }
    // The new prefix interface preserves the general path's exact ciphertext,
    // even for a nonzero message tail and a non-power-of-two output count.
    for count in [0, 1, 3, N] {
        let indices: Vec<_> = (0..count).collect();
        let mut reference = vec![0; count * N];
        run(Operation::Project(&indices), &mut reference);
        output.resize(count * N, 7);
        run(Operation::ProjectPrefix(count), &mut output);
        assert_eq!(output, reference);
    }
    for log_count in 0..=N.trailing_zeros() {
        let count = 1 << log_count;
        output.resize(count * N, 7);
        run(Operation::Expand(count), &mut output);
        // For a general input, partial expansion must retain the residue-class
        // polynomial, rather than silently promise a constant coefficient.
        for (i, cipher) in output.as_chunks::<N>().0.iter().enumerate() {
            let mut expected = vec![0; N];
            for j in (i..N).step_by(count) {
                expected[j - i] = message[j];
            }
            assert_phase(cipher, &expected, secret, q);
        }
        if count == 1 {
            assert_eq!(output, input.as_ref());
        }
    }
    for (operation, len) in [
        (Operation::Trace(0), N),
        (Operation::Reverse(3), N),
        (Operation::Reverse(N * 2), N),
        (Operation::Expand(0), 0),
        (Operation::Expand(3), 3 * N),
        (Operation::Expand(N * 2), 2 * N * N),
        (Operation::Expand(4), 3 * N),
        (Operation::Project(&[0, N]), 2 * N),
        (Operation::Project(&[0, 1]), N),
        (Operation::ProjectPrefix(N + 1), (N + 1) * N),
        (Operation::ProjectPrefix(0), N),
        (Operation::ProjectPrefix(3), 3 * N - 1),
    ] {
        let mut output = vec![7; len];
        assert!(catch_unwind(AssertUnwindSafe(|| run(operation, &mut output))).is_err());
        assert!(output.iter().all(|&value| value == 7));
    }
}

#[test]
fn ntt_trace_projection_and_expansion_match_ring_phases() {
    let modulus = BarrettModulus::new(Q);
    let table = U64NttTable::new(N.trailing_zeros(), modulus).unwrap();
    let parameters = NtruParameters::new(N, 64, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let gadget = NlevParameters::with_ntru_params(&parameters, 10, None);
    let secret = secret();
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4e54_545f_5452_4143);
    let trace = NttNtruTraceKey::generate(
        &secret,
        &key,
        &gadget,
        &table,
        &mut rng,
        &mut NttNtruGadgetEncryptContext::new(N),
    );
    let mut context = NttNtruTraceContext::new(N);
    let m = message(Q.into());
    let mut transformed = NttNtruCiphertext::<Vec<u64>>::zero(N);
    key.encrypt_encoded_to(
        &Polynomial(m.as_slice()),
        &mut transformed,
        &parameters,
        &table,
        &mut rng,
    );
    let mut input = NtruCiphertext::<Vec<u64>>::zero(N);
    transformed.write_coeff_form(&mut input, &table);
    check_operations(
        &input,
        &m,
        secret.as_slice(),
        Q.into(),
        |operation, output| match operation {
            Operation::Trace(r) => trace.apply_partial_to(
                &input,
                r,
                &mut NtruCiphertext::new(output),
                modulus,
                &table,
                &mut context,
            ),
            Operation::Reverse(r) => trace.apply_reverse_partial_to(
                &input,
                r,
                &mut NtruCiphertext::new(output),
                modulus,
                &table,
                &mut context,
            ),
            Operation::Project(indices) => trace.project_coefficients_to(
                &input,
                indices,
                output,
                modulus,
                &table,
                &mut context,
            ),
            Operation::Expand(count) => trace.expand_partial_coefficients_to(
                &input,
                count,
                output,
                modulus,
                &table,
                &mut context,
            ),
            Operation::ProjectPrefix(count) => trace.project_prefix_coefficients_to(
                &input,
                count,
                output,
                modulus,
                &table,
                &mut context,
            ),
        },
    );
    for log_count in 0..=N.trailing_zeros() {
        let count = 1 << log_count;
        let mut m = m.clone();
        m[count..].fill(0);
        key.encrypt_encoded_to(
            &Polynomial(m.as_slice()),
            &mut transformed,
            &parameters,
            &table,
            &mut rng,
        );
        transformed.write_coeff_form(&mut input, &table);
        let mut expanded = vec![7; count * N];
        trace.expand_partial_coefficients_to(
            &input,
            count,
            &mut expanded,
            modulus,
            &table,
            &mut context,
        );
        for (cipher, &value) in expanded.as_chunks::<N>().0.iter().zip(&m[..count]) {
            let mut expected = vec![0; N];
            expected[0] = value;
            assert_phase(cipher, &expected, secret.as_slice(), Q.into());
        }
    }
}

fn fourier_trace<Table: FftTable>() {
    let q = 1u128 << 64;
    let table = Table::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let parameters = NtruParameters::new(
        N,
        64u64,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let gadget = NlevParameters::with_ntru_params(&parameters, 8, Some(7));
    let secret = secret();
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(&secret, &mut fft).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4646_545f_5452_4143);
    let trace = FourierNtruTraceKey::generate(
        &secret,
        &key,
        &gadget,
        &mut fft,
        &mut rng,
        &mut FourierNtruGadgetEncryptContext::new(N),
    );
    let mut context = FourierNtruTraceContext::new(N);
    let m = message(q);
    let mut transformed = FourierNtruCiphertext::<Vec<Complex64>>::zero(N / 2);
    let mut encrypt = FourierNtruEncryptContext::new(N);
    key.encrypt_encoded_to(
        &Polynomial(m.as_slice()),
        &mut transformed,
        &parameters,
        &mut fft,
        &mut rng,
        &mut encrypt,
    );
    let mut input = NtruCiphertext::<Vec<u64>>::zero(N);
    transformed.write_torus_form(&mut input, &mut fft);
    check_operations(
        &input,
        &m,
        secret.as_slice(),
        q,
        |operation, output| match operation {
            Operation::Trace(r) => trace.apply_partial_to(
                &input,
                r,
                &mut NtruCiphertext::new(output),
                &mut fft,
                &mut context,
            ),
            Operation::Reverse(r) => trace.apply_reverse_partial_to(
                &input,
                r,
                &mut NtruCiphertext::new(output),
                &mut fft,
                &mut context,
            ),
            Operation::Project(indices) => {
                trace.project_coefficients_to(&input, indices, output, &mut fft, &mut context)
            }
            Operation::ProjectPrefix(count) => {
                trace.project_prefix_coefficients_to(&input, count, output, &mut fft, &mut context)
            }
            Operation::Expand(count) => {
                trace.expand_partial_coefficients_to(&input, count, output, &mut fft, &mut context)
            }
        },
    );
    for log_count in 0..=N.trailing_zeros() {
        let count = 1 << log_count;
        let mut m = m.clone();
        m[count..].fill(0);
        key.encrypt_encoded_to(
            &Polynomial(m.as_slice()),
            &mut transformed,
            &parameters,
            &mut fft,
            &mut rng,
            &mut encrypt,
        );
        transformed.write_torus_form(&mut input, &mut fft);
        let mut expanded = vec![7; count * N];
        trace.expand_partial_coefficients_to(&input, count, &mut expanded, &mut fft, &mut context);
        for (cipher, &value) in expanded.as_chunks::<N>().0.iter().zip(&m[..count]) {
            let mut expected = vec![0; N];
            expected[0] = value;
            assert_phase(cipher, &expected, secret.as_slice(), q);
        }
    }
}

#[test]
fn fourier_trace_projection_and_expansion_match_ring_phases() {
    fourier_trace::<RustFftTable>();
    fourier_trace::<TfheFftTable>();
}

// Deterministic zero-noise evaluation-key fixture. This is not a production RNG.
struct ZeroRng;
impl TryRng for ZeroRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        output.fill(0);
        Ok(())
    }
}
impl TryCryptoRng for ZeroRng {}

#[test]
fn reverse_trace_preserves_the_distinct_modular_and_native_halving_paths() {
    const N: usize = 4;
    let secret = NtruSecretKey::<u32>::new(vec![1, 0, 0, 0], SecretKeyDistr::UniformBinary);
    let modulus = BarrettModulus::new(257u32);
    let table = primus_ntt::UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    let params = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let params = NlevParameters::with_ntru_params(&params, 3, None);
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&secret, modulus, &table).unwrap();
    let trace = NttNtruTraceKey::generate(
        &secret,
        &key,
        &params,
        &table,
        &mut ZeroRng,
        &mut NttNtruGadgetEncryptContext::new(N),
    );
    let input = NtruCiphertext::new(vec![1u32, 2, 256, 255]);
    let mut output = NtruCiphertext::new(vec![7; N]);
    let mut context = NttNtruTraceContext::new(N);
    trace.apply_reverse_partial_to(&input, 2, &mut output, modulus, &table, &mut context);
    assert_eq!(output.as_ref(), &[1, 0, 256, 0]);
    let mut wrong = NttNtruTraceContext::new(2 * N);
    output.as_mut().fill(7);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            trace.apply_reverse_to(&input, &mut output, modulus, &table, &mut wrong);
        }))
        .is_err()
    );
    assert_eq!(output.as_ref(), &[7; N]);

    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    let params = NtruParameters::new(
        N,
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let params = NlevParameters::with_ntru_params(&params, 8, None);
    let key = FourierNtruSecretKey::try_from_coeff_secret_key(&secret, &mut fft).unwrap();
    let trace = FourierNtruTraceKey::generate(
        &secret,
        &key,
        &params,
        &mut fft,
        &mut ZeroRng,
        &mut FourierNtruGadgetEncryptContext::new(N),
    );
    let input = NtruCiphertext::new(vec![1u32, 0, u32::MAX, 0]);
    let mut context = FourierNtruTraceContext::new(N);
    trace.apply_reverse_partial_to(&input, 2, &mut output, &mut fft, &mut context);
    // floor(1/2) and floor((2^32-1)/2), then the even projection doubles them.
    assert_eq!(output.as_ref(), &[0, 0, u32::MAX - 1, 0]);
    let mut wrong = FourierNtruTraceContext::new(2 * N);
    output.as_mut().fill(7);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            trace.apply_reverse_to(&input, &mut output, &mut fft, &mut wrong);
        }))
        .is_err()
    );
    assert_eq!(output.as_ref(), &[7; N]);
}
