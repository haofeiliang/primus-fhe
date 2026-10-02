use crate::key::BootstrappingControls;

use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationQuantizer;

use crate::{ClassicControls, ServerKey, TfheParameters};

/// Coefficient buffers and Fourier external-product scratch reused online.
pub(crate) struct BlindRotationWorkspace<'a, T: TorusFftValue> {
    /// Coefficient-domain result under the accumulator secret after BR.
    pub(crate) current: Ntru<Vec<T>>,
    /// BR temporary storage in the accumulator domain.
    pub(crate) scratch: Ntru<Vec<T>>,
    pub(crate) rotation: RotationState<'a, T>,
}

impl<'a, T: TorusFftValue> BlindRotationWorkspace<'a, T> {
    /// Allocates all blind-rotation storage once.
    pub(crate) fn new<LM: primus_reduce::RingContext<T>>(
        parameters: &TfheParameters<T, LM>,
        server_key: &'a ServerKey<T>,
    ) -> Self {
        let poly_length = parameters.poly_length();
        Self {
            current: Ntru::zero(poly_length.get()),
            scratch: Ntru::zero(poly_length.get()),
            rotation: match server_key.bootstrapping_controls() {
                BootstrappingControls::Sparse(key) => RotationState::Sparse {
                    key,
                    scratch: crate::sparse::SparseWorkspace::new(parameters),
                },
                BootstrappingControls::Classic(controls) => {
                    let scratch = primus_ntru::FourierNtruCmuxWorkspace::new(
                        poly_length,
                        parameters.blind_rotation().decompose_length(),
                    );
                    if controls.is_binary() {
                        RotationState::Binary { controls, scratch }
                    } else {
                        RotationState::Ternary { controls, scratch }
                    }
                }
            },
        }
    }
}

// A validated control layout and its scratch travel together for the evaluator's lifetime.
pub(crate) enum RotationState<'a, T: TorusFftValue> {
    Sparse {
        key: &'a crate::SparseNtruBootstrappingKey<T>,
        scratch: crate::sparse::SparseWorkspace<T>,
    },
    Binary {
        controls: ClassicControls<'a>,
        scratch: primus_ntru::FourierNtruCmuxWorkspace<T>,
    },
    Ternary {
        controls: ClassicControls<'a>,
        scratch: primus_ntru::FourierNtruCmuxWorkspace<T>,
    },
}

impl<'a, T: TorusFftValue> RotationState<'a, T> {
    /// Borrows the classic material already selected with this BR workspace.
    pub(crate) fn classic_controls(&self) -> Option<ClassicControls<'a>> {
        match self {
            Self::Sparse { .. } => None,
            Self::Binary { controls, .. } | Self::Ternary { controls, .. } => Some(*controls),
        }
    }

    pub(crate) fn external_product(
        &mut self,
    ) -> &mut primus_ntru::FourierNtruExternalProductWorkspace<T> {
        match self {
            Self::Sparse { scratch, .. } => &mut scratch.external_product,
            Self::Binary { scratch, .. } => scratch.external_product_workspace(),
            Self::Ternary { scratch, .. } => scratch.external_product_workspace(),
        }
    }
}

/// Initializes and blind-rotates an encrypted native NTRU accumulator.
///
/// Writes the selected LUT phase to coefficient-domain `workspace.current`
/// under `f_acc`, reusing `workspace.scratch` as temporary storage. The caller
/// established input/LUT compatibility; `rotation_step` is the LUT's padded
/// output count (one for ordinary PBS).
pub(crate) fn blind_rotate_lookup_table_to<T, Table, LM: primus_reduce::RingContext<T>>(
    server_key: &ServerKey<T>,
    input: Lwe<&[T]>,
    lookup_table: Polynomial<&[T]>,
    rotation_step: usize,
    workspace: &mut BlindRotationWorkspace<'_, T>,
    parameters: &TfheParameters<T, LM>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let poly_length = parameters.poly_length().get();
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
    let basis = server_key.blind_rotation_basis();
    // One public layout dispatch per BR; the coordinate loop stays specialized.
    match &mut workspace.rotation {
        RotationState::Sparse { key, scratch } => {
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
        RotationState::Binary {
            controls,
            scratch: product,
        } => {
            let (positive, negative) = controls.first_controls();
            controls.initializer().lift_monomial_to(
                &positive,
                negative.as_ref(),
                &Polynomial(workspace.scratch.as_ref()),
                exponent_of(input.a()[0]),
                &mut workspace.current,
                basis,
                fft,
                product,
            );
            rotate_controls(
                &input.a()[1..],
                controls.remaining_controls(),
                &mut workspace.current,
                &mut workspace.scratch,
                exponent_of,
                |control, exponent, input, output| {
                    control.cmux_monomial_to(
                        input,
                        exponent,
                        output,
                        basis,
                        fft,
                        product.external_product_workspace(),
                    )
                },
            );
        }
        RotationState::Ternary {
            controls,
            scratch: product,
        } => {
            let (positive, negative) = controls.first_controls();
            controls.initializer().lift_monomial_to(
                &positive,
                negative.as_ref(),
                &Polynomial(workspace.scratch.as_ref()),
                exponent_of(input.a()[0]),
                &mut workspace.current,
                basis,
                fft,
                product,
            );
            rotate_controls(
                &input.a()[1..],
                controls.ternary_controls(),
                &mut workspace.current,
                &mut workspace.scratch,
                exponent_of,
                |(positive, negative), exponent, input, output| {
                    positive.cmux_ternary_monomial_to(
                        &negative, input, exponent, output, basis, fft, product,
                    )
                },
            );
        }
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
