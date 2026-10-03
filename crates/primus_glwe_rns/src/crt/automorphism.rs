use itertools::izip;
use num_traits::ConstZero;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{
    RnsGadgetSize,
    glev::{DcrtGlevIter, DcrtGlevIterMut},
    workspace::DcrtGlevMulWorkspace,
};
use primus_ntt::NttTable;
use primus_poly::{CoeffAutomorphismPermutation, CrtPolynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::secret_key::encode_secret_polynomial_to_rns;
use crate::{
    CrtGlevParameters, CrtGlweCiphertext, DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweSecretKey,
    GlweSecretKey,
};

/// Reusable workspace for CRT and DCRT automorphism operations.
///
/// Each operation overwrites the internal polynomial and GLev buffers.
/// Construct this workspace from the domain used by the operations. Reuse with
/// another domain requires the same gadget layout and RNS big-integer limb
/// width; the caller must maintain this compatibility. No rebinding is performed.
pub struct CrtGlweAutomorphismWorkspace<T: FheUint> {
    auto_crt_poly: CrtPolynomial<Vec<T>>,
    glev_workspace: DcrtGlevMulWorkspace<T>,
}

impl<T: FheUint> CrtGlweAutomorphismWorkspace<T> {
    /// Creates reusable workspace from one complete RNS gadget parameter set.
    pub fn new<M, Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        Self::from_parameters(domain.parameters())
    }

    pub(crate) fn from_parameters<M>(parameters: &CrtGlevParameters<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        let size = parameters.size();
        let glwe_size = size.rns_glwe_size();
        let crt_poly_len = glwe_size.rns_poly_len();

        let auto_crt_poly = CrtPolynomial::zero(crt_poly_len);
        let glev_workspace = DcrtGlevMulWorkspace::new(size, parameters.base_q());

        Self {
            auto_crt_poly,
            glev_workspace,
        }
    }

    pub(crate) fn as_mut(&mut self) -> (&mut CrtPolynomial<Vec<T>>, &mut DcrtGlevMulWorkspace<T>) {
        (&mut self.auto_crt_poly, &mut self.glev_workspace)
    }
}

/// Generate automorphism key data in the coefficient domain: for each
/// secret-key polynomial s_i, encrypt σ_k(s_i) under a GLEV ciphertext.
fn generate_auto_key_data<T, M, Table, R>(
    domain: &DcrtGadgetDomain<'_, T, M, Table>,
    permutation: &CoeffAutomorphismPermutation,
    sk: &GlweSecretKey<T>,
    dcrt_sk: &DcrtGlweSecretKey<T>,
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
    R: rand::Rng + rand::CryptoRng,
    M: FieldContext<T>,
{
    let params = domain.parameters();
    let poly_length = params.poly_length().get();
    let rns_poly_len = params.rns_poly_len();
    let dcrt_glev_len = params.rns_glev_len();
    let encryptor = dcrt_sk
        .try_bind_gadget(domain)
        .expect("automorphism secret key and gadget domain are incompatible");
    assert_eq!(sk.glwe_size(), params.size().rns_glwe_size().glwe_size());

    let mut key = vec![T::ZERO; params.dimension().get() * dcrt_glev_len];
    let mut auto_buffer = Zeroizing::new(vec![T::ZERO; rns_poly_len]);
    let mut auto_si = CrtPolynomial(auto_buffer.as_mut_slice());
    let mut auto_signed = Zeroizing::new(vec![T::SignedInteger::ZERO; poly_length]);

    let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);

    sk.iter().zip(key_iter).for_each(|(si, mut dcrt_glev)| {
        permutation.apply_signed_to::<T>(si, &mut auto_signed);
        encode_secret_polynomial_to_rns(
            &auto_signed,
            auto_si.as_mut(),
            params.cipher_moduli_value(),
        );

        encryptor.encrypt_crt_to(&auto_si, &mut dcrt_glev, rng);
    });

    key
}

/// Automorphism key
#[derive(Clone)]
pub struct CrtGlweAutoKey<T: FheUint> {
    key: Vec<T>,
    permutation: CoeffAutomorphismPermutation,
    size: RnsGadgetSize,
}

impl<T: FheUint> CrtGlweAutoKey<T> {
    /// Creates an automorphism key for `X -> X^degree`.
    ///
    /// # Panics
    ///
    /// Panics if `degree` is not odd and less than twice the polynomial length.
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        degree: usize,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let permutation =
            CoeffAutomorphismPermutation::new(degree, domain.parameters().poly_length());

        let key = generate_auto_key_data(domain, &permutation, sk, dcrt_sk, rng);

        Self {
            key,
            permutation,
            size: domain.size(),
        }
    }

    pub(crate) fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.size.rns_glev_len())
    }

    /// Applies this automorphism key to a CRT coefficient-domain ciphertext.
    ///
    /// `result` may not alias `ciphertext`; both must match the domain's RNS
    /// GLWE layout. The reusable workspace is overwritten.
    pub fn automorphism_to<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut CrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut CrtGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let rns_glwe_len = self.size.rns_glwe_size().rns_glwe_len();

        assert_eq!(ciphertext.as_ref().len(), rns_glwe_len);
        assert_eq!(result.as_ref().len(), rns_glwe_len);

        self.automorphism_kernel(
            ciphertext.as_view(),
            result.as_mut_view(),
            domain,
            workspace,
        );
    }

    /// Internal kernel used by composed operations.
    /// Callers must ensure workspace compatibility and input/output layouts
    /// before invoking this kernel; it performs no boundary validation.
    pub(crate) fn automorphism_kernel<M, Table>(
        &self,
        ciphertext: CrtGlweCiphertext<&[T]>,
        mut result: CrtGlweCiphertext<&mut [T]>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut CrtGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let table = domain.table();
        let rns_base = domain.rns_base();
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let permutation = &self.permutation;

        let (auto_crt_poly, glev_workspace) = workspace.as_mut();

        result.set_zero();
        let mut temp = DcrtGlweCiphertext::new(result.as_mut());

        let (a_in, b_in) = ciphertext.a_b(rns_poly_len);

        self.iter_dcrt_glev()
            .zip(a_in)
            .for_each(|(auto_key_i, in_crt_poly)| {
                crt_polynomial_automorphism_to(
                    in_crt_poly.as_ref(),
                    auto_crt_poly.as_mut(),
                    permutation,
                    moduli,
                );

                temp.add_dcrt_glev_mul_crt_polynomial_assign(
                    &auto_key_i,
                    auto_crt_poly,
                    params.basis(),
                    table,
                    rns_base,
                    glev_workspace,
                );
            });

        crt_polynomial_automorphism_to(b_in.as_ref(), auto_crt_poly.as_mut(), permutation, moduli);

        let _ = temp.into_coeff_form(table);

        let (a_out, mut b_out) = result.a_b_mut(rns_poly_len);

        a_out.for_each(|mut ai| ai.neg_assign(poly_length, moduli));

        auto_crt_poly.sub_rev_assign(&mut b_out, poly_length, moduli);
    }
}

/// Applies one shared coefficient map to each ordered CRT modulus component.
/// The caller supplies complete, matching RNS polynomials and moduli.
fn crt_polynomial_automorphism_to<T, M>(
    input: &[T],
    output: &mut [T],
    permutation: &CoeffAutomorphismPermutation,
    moduli: &[M],
) where
    T: FheUint,
    M: FieldContext<T>,
{
    let n = permutation.poly_length().get();
    for (input, mut output, &modulus) in izip!(
        PolynomialIter::new(input, n),
        PolynomialIterMut::new(output, n),
        moduli
    ) {
        permutation.apply_to(input.as_ref(), output.as_mut(), modulus);
    }
}
