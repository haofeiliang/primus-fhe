//! Observe sensitive allocations before deallocation, without reading freed memory.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    convert::Infallible,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
};

use primus_fft::{FftEngine, FftTable, RustFftTable};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruCiphertext, FourierNtruDecryptContext,
    FourierNtruEncryptContext, FourierNtruGadgetEncryptContext, FourierNtruSecretKey,
    NlevParameters, NtruError, NtruParameters, NtruSecretKey, NttNgswCiphertext,
    NttNtruGadgetEncryptContext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
use zeroize::Zeroize;

struct ObservingAllocator;
thread_local! {
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}
static WATCHED: [AtomicPtr<u8>; 8] = [const { AtomicPtr::new(ptr::null_mut()) }; 8];
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
static ERASED: AtomicBool = AtomicBool::new(true);

// A non-allocating scripted source used only to force rejection then success.
struct Words<'a>(std::slice::Iter<'a, u32>);
impl TryRng for Words<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(*self.0.next().expect("scripted u32"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from(self.try_next_u32()?) | (u64::from(self.try_next_u32()?) << 32))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        for chunk in output.chunks_mut(4) {
            chunk.copy_from_slice(&self.try_next_u32()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
impl TryCryptoRng for Words<'_> {}

// SAFETY: System owns every allocation. Recording uses no allocation, and the
// observer reads only initialized buffers before System releases their storage.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        let data = unsafe { System.alloc(layout) };
        if !data.is_null() && RECORDING.try_with(Cell::get).unwrap_or(false) {
            let index = ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            if let Some(watched) = WATCHED.get(index) {
                watched.store(data, Ordering::SeqCst);
            }
        }
        data
    }

    unsafe fn dealloc(&self, data: *mut u8, layout: Layout) {
        for watched in &WATCHED {
            if watched
                .compare_exchange(data, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let mut erased = true;
                for index in 0..layout.size() {
                    // SAFETY: tracked constructors initialize their entire
                    // allocations; the imported key's spare capacity was also
                    // initialized before truncation. Storage is still live.
                    erased &= unsafe { ptr::read_volatile(data.add(index)) } == 0;
                }
                ERASED.fetch_and(erased, Ordering::SeqCst);
                RELEASED.fetch_add(1, Ordering::SeqCst);
                break;
            }
        }
        // SAFETY: data/layout are the original allocation passed by the caller.
        unsafe { System.dealloc(data, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

// Watch construction of fully initialized secret buffers. Allocations made
// while exercising the result are outside this observation.
fn assert_erased<K>(expected: usize, create: impl FnOnce() -> K, use_value: impl FnOnce(&mut K)) {
    ALLOCATIONS.store(0, Ordering::SeqCst);
    RELEASED.store(0, Ordering::SeqCst);
    ERASED.store(true, Ordering::SeqCst);
    RECORDING.set(true);
    let mut value = create();
    RECORDING.set(false);
    use_value(&mut value);
    drop(value);
    assert_eq!(ALLOCATIONS.load(Ordering::SeqCst), expected);
    assert_eq!(RELEASED.load(Ordering::SeqCst), expected);
    assert!(
        ERASED.load(Ordering::SeqCst),
        "sensitive allocation was not erased"
    );
}

// Keep allocator observations serial: all cases share the watched allocations.
#[test]
fn secret_buffers_are_reused_and_erased() {
    const N: usize = 32;
    let distr = SecretKeyDistr::UniformBinary;
    assert_erased(
        1,
        || {
            let mut coefficients = vec![1i32; 2 * N];
            coefficients.truncate(N);
            NtruSecretKey::<u32>::new(coefficients, distr)
        },
        |_| {},
    );

    let mut coefficients = vec![0i32; N];
    // f = X is invertible in both domains and exercises nonzero real and
    // imaginary components in the Fourier key and its inverse.
    coefficients[1] = 1;
    let mut coefficient_key = NtruSecretKey::<u32>::new(coefficients, distr);
    let modulus = BarrettModulus::new(132_120_577u32);
    let ntt = UintNttTable::new(N.trailing_zeros(), modulus).unwrap();
    assert_erased(
        2,
        || NttNtruSecretKey::try_from_coeff_secret_key(&coefficient_key, modulus, &ntt).unwrap(),
        |_| {},
    );
    let table = RustFftTable::new(N.trailing_zeros()).unwrap();
    let mut fft = FftEngine::new(&table);
    assert_erased(
        3,
        || FourierNtruSecretKey::try_from_coeff_secret_key(&coefficient_key, &mut fft).unwrap(),
        |_| {},
    );

    let mut ntt_key =
        NttNtruSecretKey::try_from_coeff_secret_key(&coefficient_key, modulus, &ntt).unwrap();
    let mut fourier_key =
        FourierNtruSecretKey::try_from_coeff_secret_key(&coefficient_key, &mut fft).unwrap();
    let ntt_params = NtruParameters::new(N, 4, modulus, distr, 0.7);
    let fourier_params = NtruParameters::new(N, 4, NativeModulus::new(), distr, 0.7);
    let ntt_gadget = NlevParameters::with_ntru_params(&ntt_params, 4, Some(3));
    let fourier_gadget = NlevParameters::with_ntru_params(&fourier_params, 4, Some(3));
    let mut rng = StdRng::seed_from_u64(42);
    let message = Polynomial::new(vec![1u32; N]);
    let mut ntt_output = NttNgswCiphertext::<Vec<u32>>::zero(ntt_gadget.nlev_len());
    let mut fourier_output =
        FourierNgswCiphertext::<Vec<_>>::zero(fourier_gadget.fourier_nlev_len());
    let mut cipher = FourierNtruCiphertext::<Vec<_>>::zero(N / 2);
    let mut phase = Polynomial::new(vec![0u32; N]);

    // Explicit zeroization preserves reusable workspace lengths. A second
    // operation fills each workspace again before its destructor is observed.
    assert_erased(
        1,
        || NttNtruGadgetEncryptContext::new(N),
        |context| {
            for _ in 0..2 {
                context.zeroize();
                ntt_key.encrypt_ngsw_to(
                    &message,
                    &mut ntt_output,
                    &ntt_gadget,
                    &ntt,
                    &mut rng,
                    context,
                );
            }
        },
    );
    assert_erased(
        3,
        || FourierNtruGadgetEncryptContext::new(N),
        |context| {
            for _ in 0..2 {
                context.zeroize();
                fourier_key.encrypt_ngsw_to(
                    &message,
                    &mut fourier_output,
                    &fourier_gadget,
                    &mut fft,
                    &mut rng,
                    context,
                );
            }
        },
    );
    assert_erased(
        1,
        || FourierNtruEncryptContext::new(N),
        |context| {
            for _ in 0..2 {
                context.zeroize();
                fourier_key.encrypt_to(
                    &message,
                    &mut cipher,
                    &fourier_params,
                    &mut fft,
                    &mut rng,
                    context,
                );
            }
        },
    );
    assert_erased(
        1,
        || FourierNtruDecryptContext::new(N),
        |context| {
            for _ in 0..2 {
                context.zeroize();
                fourier_key.phase_to(&cipher, &mut phase, &mut fft, context);
            }
        },
    );

    // f = X - root has one zero NTT evaluation and other nonzero values:
    // failed inversion must erase the partially constructed transformed key.
    let mut roots = vec![0u32; N];
    roots[1] = 1;
    ntt.transform_slice(&mut roots);
    let mut nonunit = vec![0i32; N];
    nonunit[0] = -(roots[0] as i32);
    nonunit[1] = 1;
    let nonunit = NtruSecretKey::<u32>::new(nonunit, distr);
    assert_erased(
        2,
        || NttNtruSecretKey::try_from_coeff_secret_key(&nonunit, modulus, &ntt),
        |result| assert!(matches!(result, Err(NtruError::NonInvertibleSecretKey))),
    );

    // Reject f = 0, then accept f = X. The allocation count must stay fixed
    // across retries, and the returned key/inverse must contain the new candidate.
    for padded in [false, true] {
        // Uniform binary sampling draws one extra word for the remainder,
        // including when the full 32-coefficient block leaves an empty remainder.
        let script: &[u32] = if padded { &[0, 2] } else { &[0, 0, 2, 0] };
        let mut words = Words(script.iter());
        assert_erased(
            3,
            || {
                if padded {
                    NttNtruSecretKey::generate_padded_binary_pair(
                        &ntt_params,
                        N / 2,
                        &ntt,
                        &mut words,
                    )
                } else {
                    NttNtruSecretKey::generate_pair(&ntt_params, &ntt, &mut words)
                }
            },
            |result| {
                let (coeff, key) = result.as_ref().unwrap();
                assert_eq!(coeff.as_slice(), coefficient_key.as_slice());
                let cipher = key.encrypt(&message, &ntt_params, &ntt, &mut rng);
                assert_eq!(
                    key.decrypt(&cipher, &ntt_params, &ntt).as_ref(),
                    message.as_ref()
                );
            },
        );
        assert!(words.0.next().is_none());

        let mut words = Words(script.iter());
        assert_erased(
            4,
            || {
                if padded {
                    FourierNtruSecretKey::generate_padded_binary_pair(
                        &fourier_params,
                        N / 2,
                        &mut fft,
                        &mut words,
                    )
                } else {
                    FourierNtruSecretKey::generate_pair(&fourier_params, &mut fft, &mut words)
                }
            },
            |result| {
                let (coeff, key) = result.as_ref().unwrap();
                assert_eq!(coeff.as_slice(), coefficient_key.as_slice());
                let mut check_fft = FftEngine::new(&table);
                let mut encrypt = FourierNtruEncryptContext::new(N);
                let mut decrypt = FourierNtruDecryptContext::new(N);
                let cipher = key.encrypt(
                    &message,
                    &fourier_params,
                    &mut check_fft,
                    &mut rng,
                    &mut encrypt,
                );
                assert_eq!(
                    key.decrypt(&cipher, &fourier_params, &mut check_fft, &mut decrypt)
                        .as_ref(),
                    message.as_ref(),
                );
            },
        );
        assert!(words.0.next().is_none());
    }

    // Every weight-two candidate is nonzero but fails the parity check before
    // FFT. Both retry paths allocate all four buffers once and erase them when
    // the search exhausts its attempt bound.
    let rejecting_params = NtruParameters::new(
        N,
        4,
        NativeModulus::<u32>::new(),
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 2 },
        0.7,
    );
    for padded in [false, true] {
        assert_erased(
            4,
            || {
                if padded {
                    FourierNtruSecretKey::generate_padded_binary_pair(
                        &rejecting_params,
                        N / 2,
                        &mut fft,
                        &mut rng,
                    )
                } else {
                    FourierNtruSecretKey::generate_pair(&rejecting_params, &mut fft, &mut rng)
                }
            },
            |result| assert!(matches!(result, Err(NtruError::KeyGenerationExhausted))),
        );
    }

    coefficient_key.zeroize();
    ntt_key.zeroize();
    fourier_key.zeroize();
    assert!(coefficient_key.as_slice().is_empty());
    assert_eq!(ntt_key.poly_length(), 0);
    assert_eq!(fourier_key.poly_length(), 0);

    // Reject a destroyed Fourier key even in release mode: multiplying by an
    // empty inverse would otherwise leave the encoded message and noise exposed.
    let mut context = FourierNtruEncryptContext::new(N);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fourier_key.encrypt_to(
                &message,
                &mut cipher,
                &fourier_params,
                &mut fft,
                &mut rng,
                &mut context,
            );
        }))
        .is_err()
    );
}
