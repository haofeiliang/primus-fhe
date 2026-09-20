use primus_data::Data;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_tfhe::rotation::RotationQuantizer;

use crate::{ServerKey, TfheParameters};

/// Coefficient buffers and Fourier external-product scratch reused online.
pub(crate) struct BlindRotationWorkspace<'a, T: TorusFftValue> {
    /// Coefficient-domain result under the accumulator secret after BR.
    pub(crate) current: Ntru<Vec<T>>,
    /// BR temporary storage, then coefficient output under the client secret after KS.
    pub(crate) scratch: Ntru<Vec<T>>,
    pub(crate) rotation: RotationContext<'a, T>,
}

impl<'a, T: TorusFftValue> BlindRotationWorkspace<'a, T> {
    /// Allocates all blind-rotation storage once.
    pub(crate) fn new(parameters: &TfheParameters<T>, server_key: &'a ServerKey<T>) -> Self {
        let poly_length = parameters.poly_length();
        Self {
            current: Ntru::zero(poly_length),
            scratch: Ntru::zero(poly_length),
            rotation: if let Some(key) = server_key.sparse_bootstrapping_key() {
                RotationContext::Sparse {
                    key,
                    scratch: crate::sparse::SparseWorkspace::new(parameters),
                }
            } else if parameters.external_lwe().secret_key_distr().is_binary() {
                RotationContext::Binary {
                    controls: server_key.classic_controls(),
                    scratch: primus_ntru::FourierNtruExternalProductContext::new(poly_length),
                }
            } else {
                RotationContext::Ternary {
                    controls: server_key.classic_controls(),
                    scratch: primus_ntru::FourierNtruTernaryCmuxContext::new(
                        poly_length,
                        parameters.blind_rotation().decompose_length(),
                    ),
                }
            },
        }
    }
}

// A validated control layout and its scratch travel together for the evaluator's lifetime.
pub(crate) enum RotationContext<'a, T: TorusFftValue> {
    Sparse {
        key: &'a crate::SparseNtruBootstrappingKey<T>,
        scratch: crate::sparse::SparseWorkspace<T>,
    },
    Binary {
        controls: &'a [primus_fft::Complex64],
        scratch: primus_ntru::FourierNtruExternalProductContext<T>,
    },
    Ternary {
        controls: &'a [primus_fft::Complex64],
        scratch: primus_ntru::FourierNtruTernaryCmuxContext<T>,
    },
}

impl<T: TorusFftValue> RotationContext<'_, T> {
    pub(crate) fn external_product(
        &mut self,
    ) -> &mut primus_ntru::FourierNtruExternalProductContext<T> {
        match self {
            Self::Sparse { scratch, .. } => &mut scratch.external_product,
            Self::Binary { scratch, .. } => scratch,
            Self::Ternary { scratch, .. } => scratch.external_product_context(),
        }
    }
}

/// Initializes and blind-rotates an encrypted native NTRU accumulator.
///
/// Writes the selected LUT phase to coefficient-domain `workspace.current`
/// under `f_acc`, reusing `workspace.scratch` as temporary storage. The caller
/// established input/LUT compatibility; `rotation_step` is the LUT's padded
/// output count (one for ordinary PBS).
pub(crate) fn blind_rotate_lookup_table_to<T, Table, A>(
    server_key: &ServerKey<T>,
    input: &Lwe<A>,
    lookup_table: &PolynomialOwned<T>,
    rotation_step: usize,
    workspace: &mut BlindRotationWorkspace<'_, T>,
    parameters: &TfheParameters<T>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: Data<Elem = T>,
{
    let poly_length = parameters.poly_length();
    let two_n = poly_length * 2;
    let input_modulus = parameters.external_lwe().cipher_modulus();
    let quantizer = if rotation_step == 1 {
        parameters.rotation_quantizer()
    } else {
        RotationQuantizer::new(input_modulus, two_n, rotation_step)
    };
    let exponent_of = |value| quantizer.exponent(value);
    let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
    lookup_table.mul_monomial_to(
        initial_exponent,
        &mut Polynomial(workspace.scratch.as_mut()),
        NativeModulus::new(),
    );
    // Evaluator binding checked the initializer's shape/basis; this workspace
    // was constructed at the same ring length. NLev[1] encrypts the rotated LUT.
    server_key.initializer().external_product_to(
        &Polynomial(workspace.scratch.as_ref()),
        &mut workspace.current,
        server_key.blind_rotation_basis(),
        fft,
        workspace.rotation.external_product(),
    );

    let basis = server_key.blind_rotation_basis();
    let control_len = server_key.initializer().as_ref().len();
    // One public layout dispatch per BR; the coordinate loop stays specialized.
    match &mut workspace.rotation {
        RotationContext::Sparse { key, scratch } => {
            quantizer.exponent_slice_to(input.a(), &mut scratch.exponents);
            crate::sparse::rotate_buckets(
                key,
                scratch,
                &mut workspace.current,
                &mut workspace.scratch,
                basis,
                fft,
            );
        }
        RotationContext::Binary {
            controls,
            scratch: product,
        } => rotate_controls(
            input.a(),
            controls
                .chunks_exact(control_len)
                .map(primus_lattice::ngsw::FourierNgsw::new),
            &mut workspace.current,
            &mut workspace.scratch,
            exponent_of,
            |control, exponent, input, output| {
                control.cmux_monomial_to(input, exponent, output, basis, fft, product)
            },
        ),
        RotationContext::Ternary {
            controls,
            scratch: product,
        } => rotate_controls(
            input.a(),
            controls.chunks_exact(2 * control_len).map(|pair| {
                let (positive, negative) = pair.split_at(control_len);
                (
                    primus_lattice::ngsw::FourierNgsw::new(positive),
                    primus_lattice::ngsw::FourierNgsw::new(negative),
                )
            }),
            &mut workspace.current,
            &mut workspace.scratch,
            exponent_of,
            |(positive, negative), exponent, input, output| {
                positive.cmux_ternary_monomial_to(
                    &negative, input, exponent, output, basis, fft, product,
                )
            },
        ),
    }
}

// Own both buffers so the final result can stay in `current` by swapping them.
fn rotate_controls<T: TorusFftValue, I: Iterator>(
    input: &[T],
    controls: I,
    current: &mut Ntru<Vec<T>>,
    scratch: &mut Ntru<Vec<T>>,
    exponent_of: impl Fn(T) -> usize,
    mut step: impl FnMut(I::Item, usize, &Ntru<Vec<T>>, &mut Ntru<Vec<T>>),
) {
    let mut output_is_current = true;
    for (&coefficient, control) in input.iter().zip(controls) {
        let exponent = exponent_of(coefficient);
        if exponent == 0 {
            continue;
        }
        if output_is_current {
            step(control, exponent, current, scratch);
        } else {
            step(control, exponent, scratch, current);
        }
        output_is_current = !output_is_current;
    }
    if !output_is_current {
        core::mem::swap(current, scratch);
    }
}
