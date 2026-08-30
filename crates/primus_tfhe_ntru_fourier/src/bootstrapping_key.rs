use primus_data::Data;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_tfhe::backend_support::modulus_switch;

use crate::{ServerKey, TfheParameters};

/// Coefficient buffers and Fourier external-product scratch reused online.
pub(crate) struct BlindRotationWorkspace<T: TorusFftValue> {
    pub(crate) current: Ntru<Vec<T>>,
    pub(crate) scratch: Ntru<Vec<T>>,
    pub(crate) external_product: primus_ntru::FourierNtruExternalProductContext<T>,
}

impl<T: TorusFftValue> BlindRotationWorkspace<T> {
    /// Allocates all blind-rotation storage once.
    pub(crate) fn new(poly_length: usize) -> Self {
        Self {
            current: Ntru::zero(poly_length),
            scratch: Ntru::zero(poly_length),
            external_product: primus_ntru::FourierNtruExternalProductContext::new(poly_length),
        }
    }
}

/// Blind-rotates a LUT and initializes an encrypted native NTRU accumulator.
///
/// On return, `workspace.current` contains the encrypted selected LUT phase.
pub(crate) fn blind_rotate_lookup_table_to<T, Table, A>(
    server_key: &ServerKey,
    input: &Lwe<A>,
    lookup_table: &PolynomialOwned<T>,
    workspace: &mut BlindRotationWorkspace<T>,
    parameters: &TfheParameters<T>,
    fft: &mut FftEngine<'_, Table>,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: Data<Elem = T>,
{
    let poly_length = parameters.poly_length();
    let two_n = poly_length * 2;
    let input_modulus = parameters.external_lwe().cipher_modulus_value();
    let exponent_of = |value| modulus_switch(value, input_modulus, two_n);
    let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
    lookup_table.mul_monomial_to(
        initial_exponent,
        &mut Polynomial(workspace.scratch.as_mut()),
        NativeModulus::new(),
    );
    server_key.initializer().key_switch_to(
        &workspace.scratch,
        &mut workspace.current,
        parameters.bootstrapping(),
        fft,
        &mut workspace.external_product,
    );

    let basis = parameters.bootstrapping().basis();
    let mut output_is_current = true;
    for (&coefficient, control) in input.a().iter().zip(server_key.iter_controls()) {
        let exponent = exponent_of(coefficient);
        if exponent == 0 {
            continue;
        }
        if output_is_current {
            control.cmux_monomial_to(
                &workspace.current,
                exponent,
                &mut workspace.scratch,
                basis,
                fft,
                &mut workspace.external_product,
            );
        } else {
            control.cmux_monomial_to(
                &workspace.scratch,
                exponent,
                &mut workspace.current,
                basis,
                fft,
                &mut workspace.external_product,
            );
        }
        output_is_current = !output_is_current;
    }
    if !output_is_current {
        workspace
            .current
            .as_mut()
            .copy_from_slice(workspace.scratch.as_ref());
    }
}
