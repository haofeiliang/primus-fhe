use primus_integer::FheUint;
use primus_lattice::{lwe::Lwe, ntru::Ntru};
use primus_ntt::NttTable;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_tfhe::backend_support::modulus_switch;

use crate::{ServerKey, TfheParameters};

/// Coefficient buffers and external-product scratch reused by one evaluator.
pub(crate) struct BlindRotationWorkspace<T: FheUint> {
    pub(crate) current: Ntru<Vec<T>>,
    pub(crate) scratch: Ntru<Vec<T>>,
    pub(crate) external_product: primus_ntru::NttNtruExternalProductContext<T>,
}

impl<T: FheUint> BlindRotationWorkspace<T> {
    /// Allocates all NTT blind-rotation storage once.
    pub(crate) fn new(poly_length: usize) -> Self {
        Self {
            current: Ntru::zero(poly_length),
            scratch: Ntru::zero(poly_length),
            external_product: primus_ntru::NttNtruExternalProductContext::new(poly_length),
        }
    }
}

/// Blind-rotates a lookup table and initializes an encrypted NTRU accumulator.
///
/// On return, `workspace.current` contains an `NTRU_f_acc` encryption of the
/// selected LUT phase.
pub(crate) fn blind_rotate_lookup_table_to<T, Table, A>(
    server_key: &ServerKey<T>,
    input: &Lwe<A>,
    lookup_table: &PolynomialOwned<T>,
    workspace: &mut BlindRotationWorkspace<T>,
    parameters: &TfheParameters<T>,
    ntt: &Table,
) where
    T: FheUint,
    Table: NttTable<ValueT = T>,
    A: primus_data::RawData<Elem = T> + primus_data::Data,
{
    let poly_length = parameters.poly_length();
    let two_n = poly_length * 2;
    let input_modulus = parameters.external_lwe().cipher_modulus_value();
    let exponent_of = |value| modulus_switch(value, input_modulus, two_n);
    let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
    lookup_table.mul_monomial_to(
        initial_exponent,
        &mut Polynomial(workspace.scratch.as_mut()),
        parameters.bootstrapping().ntru().cipher_modulus(),
    );
    server_key.initializer().key_switch_to(
        &workspace.scratch,
        &mut workspace.current,
        parameters.bootstrapping(),
        ntt,
        &mut workspace.external_product,
    );

    let basis = parameters.bootstrapping().basis();
    let modulus = parameters.bootstrapping().ntru().cipher_modulus();
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
                modulus,
                ntt,
                &mut workspace.external_product,
            );
        } else {
            control.cmux_monomial_to(
                &workspace.scratch,
                exponent,
                &mut workspace.current,
                basis,
                modulus,
                ntt,
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
