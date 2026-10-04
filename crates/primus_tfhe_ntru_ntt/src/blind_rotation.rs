use crate::key::BootstrappingControls;

use primus_integer::FheUint;
use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_ntru::{NttNtruCmuxWorkspace, NttNtruExternalProductWorkspace};
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationModulusSwitch;

use crate::{
    BlindRotationKey, ClassicControls, SparseNtruBootstrappingKey, TfheParameters,
    sparse::{SparseWorkspace, rotate_buckets},
};

/// Coefficient buffers and external-product scratch reused by one evaluator.
pub(crate) struct BlindRotationWorkspace<'a, T: FheUint> {
    /// Coefficient-domain result under the accumulator secret after BR.
    pub(crate) current: Ntru<Vec<T>>,
    /// BR temporary storage in the accumulator domain.
    pub(crate) scratch: Ntru<Vec<T>>,
    pub(crate) rotation: RotationState<'a, T>,
}

impl<'a, T: FheUint> BlindRotationWorkspace<'a, T> {
    /// Allocates all NTT blind-rotation storage once.
    pub(crate) fn new<LM: primus_reduce::RingContext<T>>(
        parameters: &TfheParameters<T, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
    ) -> Self {
        let poly_length = parameters.poly_length();
        Self {
            current: Ntru::zero(poly_length.get()),
            scratch: Ntru::zero(poly_length.get()),
            rotation: match blind_rotation_key.bootstrapping_controls() {
                BootstrappingControls::Sparse(key) => RotationState::Sparse {
                    key,
                    scratch: SparseWorkspace::new(parameters),
                },
                BootstrappingControls::Classic(controls) => {
                    let scratch = NttNtruCmuxWorkspace::new(
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
pub(crate) enum RotationState<'a, T: FheUint> {
    Sparse {
        key: &'a SparseNtruBootstrappingKey<T>,
        scratch: SparseWorkspace<T>,
    },
    Binary {
        controls: ClassicControls<'a, T>,
        scratch: NttNtruCmuxWorkspace<T>,
    },
    Ternary {
        controls: ClassicControls<'a, T>,
        scratch: NttNtruCmuxWorkspace<T>,
    },
}

impl<'a, T: FheUint> RotationState<'a, T> {
    pub(crate) fn external_product(&mut self) -> &mut NttNtruExternalProductWorkspace<T> {
        match self {
            Self::Sparse { scratch, .. } => &mut scratch.external_product,
            Self::Binary { scratch, .. } => scratch.external_product_workspace(),
            Self::Ternary { scratch, .. } => scratch.external_product_workspace(),
        }
    }
}

/// Initializes and blind-rotates an encrypted NTRU accumulator.
///
/// Writes the selected LUT phase to coefficient-domain `workspace.current`
/// under `f_acc`, reusing `workspace.scratch` as temporary storage. The caller
/// established input/LUT compatibility; `rotation_step` is the LUT's padded
/// output count (one for ordinary PBS).
pub(crate) fn blind_rotate_lookup_table_to<T, Table, LM: primus_reduce::RingContext<T>>(
    blind_rotation_key: &BlindRotationKey<T>,
    input: Lwe<&[T]>,
    lookup_table: Polynomial<&[T]>,
    rotation_step: usize,
    workspace: &mut BlindRotationWorkspace<'_, T>,
    parameters: &TfheParameters<T, LM>,
    ntt: &Table,
) where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    let poly_length = parameters.poly_length().get();
    let two_n = poly_length * 2;

    let input_modulus = parameters.external_lwe().cipher_modulus();
    let modulus = parameters.accumulator_ntru().cipher_modulus();

    let modulus_switch = if rotation_step == 1 {
        parameters.rotation_modulus_switch()
    } else {
        RotationModulusSwitch::new(input_modulus, two_n, rotation_step)
    };
    let exponent_of = |value| modulus_switch.exponent(value);
    let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);

    lookup_table.mul_monomial_to(
        initial_exponent,
        &mut Polynomial(workspace.scratch.as_mut()),
        modulus,
    );

    let basis = blind_rotation_key.blind_rotation_basis();

    // One public layout dispatch per BR; the coordinate loop stays specialized.
    match &mut workspace.rotation {
        RotationState::Sparse { key, scratch } => {
            modulus_switch.exponent_slice_to(input.a(), &mut scratch.exponents);
            rotate_buckets(
                key,
                scratch,
                &mut workspace.current,
                &mut workspace.scratch,
                basis,
                modulus,
                ntt,
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
                modulus,
                ntt,
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
                        modulus,
                        ntt,
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
                modulus,
                ntt,
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
                        &negative, input, exponent, output, basis, modulus, ntt, product,
                    )
                },
            );
        }
    }
}

// Own both buffers so the final result can stay in `current` by swapping them.
fn rotate_controls<T: FheUint, I: Iterator>(
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
