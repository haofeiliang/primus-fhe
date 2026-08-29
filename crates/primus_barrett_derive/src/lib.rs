use darling::FromDeriveInput;
use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod barrett;
mod modulus;

pub(crate) use modulus::Modulus;

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(modulus), supports(struct_unit))]
struct BarrettModulusInput {
    vis: syn::Visibility,
    ident: syn::Ident,
    ty: syn::Path,
    value: syn::LitInt,
}

/// Derives a zero-sized Barrett modulus context for a compile-time constant.
///
/// The input must be a unit struct. The `modulus` attribute accepts a bare
/// unsigned integer type (`u16`, `u32`, or `u64`) and a modulus satisfying
/// `1 < value < 2^(BITS - 2)`. Invalid inputs produce a compile-time error.
///
/// The macro generates associated `value()` and `ratio()` functions together
/// with the scalar, slice, lazy-reduction, inverse, and dot-product traits used
/// by `primus_modulus`. It also implements `Copy`, `Clone`, `PartialEq`, `Eq`,
/// `Debug`, and `Hash`; do not derive those traits separately. When the SIMD
/// feature is enabled, the generated slice operations use the corresponding
/// SIMD kernels.
///
/// # Example
///
/// ```ignore
/// use primus_modulus::Barrett;
///
/// #[derive(Barrett)]
/// #[modulus(ty = u32, value = 536813569)]
/// struct Modulus;
///
/// assert_eq!(Modulus::value(), 536_813_569);
/// ```
#[proc_macro_derive(Barrett, attributes(modulus))]
pub fn derive_barrett(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let parsed = match BarrettModulusInput::from_derive_input(&input) {
        Ok(v) => v,
        Err(e) => return e.write_errors().into(),
    };

    barrett::derive(&parsed)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
