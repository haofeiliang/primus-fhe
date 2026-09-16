use primus_data::Data;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_tfhe::backend_support::RotationQuantizer;

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
// The caller validates LUT compatibility; the rotation step equals the
// padded output count.
// A rotation step of one preserves the ordinary PBS modulus-switching path.
pub(crate) fn blind_rotate_lookup_table_to<T, Table, A>(
    server_key: &ServerKey<T>,
    input: &Lwe<A>,
    lookup_table: &PolynomialOwned<T>,
    rotation_step: usize,
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
        server_key.bootstrapping_basis(),
        fft,
        &mut workspace.external_product,
    );

    let basis = server_key.bootstrapping_basis();
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
