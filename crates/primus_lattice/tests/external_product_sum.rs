//! Fused NLEV sums: independent polynomial oracle, exact NTT differential,
//! Fourier torus error, empty sums, pair counts and dirty workspace reuse.
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_lattice::{
    nlev::{FourierNlev, FourierNlevOwned, Nlev, NttNlev},
    ntru::Ntru,
    workspace::{FourierNtruExternalProductWorkspace, NttNtruExternalProductWorkspace},
};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_poly::{Polynomial, PolynomialIter};
use primus_reduce::{Reduce, RingContext};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 16;

struct SumFixture<T: FheUint> {
    gadgets: Vec<Nlev<Vec<T>>>,
    inputs: Vec<Polynomial<Vec<T>>>,
    messages: Vec<Polynomial<Vec<T>>>,
}

// With f=1 a noiseless NLEV is just its message multiplied by every gadget
// weight. Dense small signed messages force all terms and negacyclic wrapping
// to contribute, rather than reducing the sum to a one-hot copy.
fn fixture<T: FheUint, M: RingContext<T>>(
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    input: Vec<T>,
) -> SumFixture<T> {
    let inputs: Vec<_> = PolynomialIter::new(&input, N)
        .map(|p| Polynomial::new(p.as_ref().to_vec()))
        .collect();
    let messages: Vec<_> = (0..inputs.len())
        .map(|j| {
            Polynomial::new(
                (0..N)
                    .map(|i| {
                        let small = T::as_from((i * 3 + j) % 5);
                        if (i + j) % 2 == 0 {
                            small
                        } else {
                            modulus.reduce_neg(small)
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let gadgets = messages
        .iter()
        .map(|message| {
            let mut gadget = Nlev::zero(basis.decompose_length() * N);
            for (scalar, mut row) in basis.scalar_iter().zip(gadget.iter_ntru_mut(N)) {
                message.mul_scalar_to(scalar, &mut Polynomial::new(row.as_mut()), modulus);
            }
            gadget
        })
        .collect();
    SumFixture {
        gadgets,
        inputs,
        messages,
    }
}

fn expected_sum<T: FheUint, M: RingContext<T>>(
    inputs: &[Polynomial<Vec<T>>],
    messages: &[Polynomial<Vec<T>>],
    modulus: M,
) -> Polynomial<Vec<T>> {
    let mut sum = Polynomial::zero(N);
    let mut product = Polynomial::<Vec<T>>::zero(N);
    for (input, message) in inputs.iter().zip(messages) {
        input.naive_mul_to(message, &mut product, modulus);
        sum.add_assign(&product, modulus);
    }
    sum
}

// Counts are checked before writes, including either side being longer. Each
// valid call reuses dirty output/scratch, ending with an empty sum that clears it.
fn ntt<T: FheUint, Table: NttTable<ValueT = T>>(q: T, table: Table) {
    let modulus = BarrettModulus::new(q);
    // Both primes have bit widths divisible by three: no bits are dropped,
    // so the independent polynomial oracle is exact.
    let basis = ApproxSignedBasis::new(Some(q), 3, None);
    let values = (0..3 * N)
        .map(|i| modulus.reduce(T::as_from(i * 997 + 1)))
        .collect();
    let SumFixture {
        gadgets,
        inputs,
        messages,
    } = fixture(&basis, modulus, values);
    let gadgets: Vec<_> = gadgets
        .into_iter()
        .map(|g| g.into_ntt_form(&table))
        .collect();
    let mut workspace = NttNtruExternalProductWorkspace::new(N);
    let mut output = Ntru::new(vec![T::MAX; N]);
    for count in [3, 1, 0] {
        let mut separate = Ntru::<Vec<T>>::zero(N);
        let mut product = Ntru::<Vec<T>>::zero(N);
        for (gadget, input) in gadgets[..count].iter().zip(&inputs[..count]) {
            gadget.external_product_to(
                input,
                &mut product,
                &basis,
                modulus,
                &table,
                &mut workspace,
            );
            separate.add_assign(&product, modulus);
        }
        NttNlev::external_product_sum_to(
            &gadgets[..count],
            &inputs[..count],
            output.as_mut_view(),
            &basis,
            modulus,
            &table,
            &mut workspace,
        );
        assert_eq!(output.as_ref(), separate.as_ref());
        assert_eq!(
            output.as_ref(),
            expected_sum(&inputs[..count], &messages[..count], modulus).as_ref()
        );
    }
    for (gadgets, inputs) in [(&gadgets[..2], &inputs[..1]), (&gadgets[..1], &inputs[..2])] {
        output.as_mut().fill(T::ONE);
        assert!(
            catch_unwind(AssertUnwindSafe(|| NttNlev::external_product_sum_to(
                gadgets,
                inputs,
                output.as_mut_view(),
                &basis,
                modulus,
                &table,
                &mut workspace,
            )))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == T::ONE));
    }
    let short = [Polynomial::new(&inputs[0].as_ref()[..N - 1])];
    assert!(
        catch_unwind(AssertUnwindSafe(|| NttNlev::external_product_sum_to(
            &gadgets[..1],
            &short,
            output.as_mut_view(),
            &basis,
            modulus,
            &table,
            &mut workspace,
        )))
        .is_err()
    );
}

#[test]
fn ntt_sum_matches_separate_products_and_polynomial_oracle() {
    ntt(
        257u32,
        U32NttTable::new(4, BarrettModulus::new(257u32)).unwrap(),
    );
    ntt(
        998_244_353u64,
        U64NttTable::new(4, BarrettModulus::new(998_244_353u64)).unwrap(),
    );
}

// The independent integer convolution is the phase oracle for f=1. u64 includes
// low bits that FFT cannot represent exactly; allow an absolute torus error of
// 2^-42 (one unit for u32), not bitwise equality with separately rounded products.
fn fourier<T: TorusFftValue, Table: FftTable>() {
    let modulus = NativeModulus::<T>::new();
    let basis = ApproxSignedBasis::new(None, 8, None);
    let table = Table::new(4).unwrap();
    let mut fft = FftEngine::new(&table);
    let values = (0..3 * N)
        .map(|i| T::as_from((i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
        .collect();
    let SumFixture {
        gadgets,
        inputs,
        messages,
    } = fixture(&basis, modulus, values);
    let gadgets: Vec<_> = gadgets
        .iter()
        .map(|g| {
            let mut transformed = FourierNlevOwned::zero(basis.decompose_length() * N / 2);
            g.write_fourier_form(&mut transformed, &mut fft);
            transformed
        })
        .collect();
    let mut workspace = FourierNtruExternalProductWorkspace::new(N);
    let mut output = Ntru::new(vec![T::MAX; N]);
    let tolerance = T::ONE << T::BITS.saturating_sub(42);
    for count in [3, 1, 0] {
        let mut separate = Ntru::<Vec<T>>::zero(N);
        let mut product = Ntru::<Vec<T>>::zero(N);
        for (gadget, input) in gadgets[..count].iter().zip(&inputs[..count]) {
            gadget.external_product_to(input, &mut product, &basis, &mut fft, &mut workspace);
            separate.add_assign(&product, modulus);
        }
        FourierNlev::external_product_sum_to(
            &gadgets[..count],
            &inputs[..count],
            output.as_mut_view(),
            &basis,
            &mut fft,
            &mut workspace,
        );
        let expected = expected_sum(&inputs[..count], &messages[..count], modulus);
        for ((&actual, &expected), &separate) in output
            .as_ref()
            .iter()
            .zip(expected.as_ref())
            .zip(separate.as_ref())
        {
            for reference in [expected, separate] {
                let distance = actual
                    .wrapping_sub(reference)
                    .min(reference.wrapping_sub(actual));
                assert!(
                    distance <= tolerance,
                    "distance={distance:?}, tolerance={tolerance:?}"
                );
            }
        }
        if count == 0 {
            assert!(output.as_ref().iter().all(|&x| x == T::ZERO));
        }
    }
    for (gadgets, inputs) in [(&gadgets[..2], &inputs[..1]), (&gadgets[..1], &inputs[..2])] {
        output.as_mut().fill(T::ONE);
        assert!(
            catch_unwind(AssertUnwindSafe(|| FourierNlev::external_product_sum_to(
                gadgets,
                inputs,
                output.as_mut_view(),
                &basis,
                &mut fft,
                &mut workspace,
            )))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == T::ONE));
    }
    let short = [Polynomial::new(&inputs[0].as_ref()[..N - 1])];
    assert!(
        catch_unwind(AssertUnwindSafe(|| FourierNlev::external_product_sum_to(
            &gadgets[..1],
            &short,
            output.as_mut_view(),
            &basis,
            &mut fft,
            &mut workspace,
        )))
        .is_err()
    );
}

#[test]
fn fourier_sum_preserves_torus_phase() {
    fourier::<u32, RustFftTable>();
    fourier::<u64, RustFftTable>();
    fourier::<u32, TfheFftTable>();
    fourier::<u64, TfheFftTable>();
}
