//! Backend-specific numerical parameters for the shared PBS workloads.
use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_tfhe_glwe::PbsOrder;
use primus_tfhe_glwe_ntt::TfheParameters;
use primus_tfhe_test_support::benchmark::{GLWE_STD_DEV, LWE_STD_DEV, PbsWorkload};

pub fn parameters_with_order<T: FheUint>(
    order: PbsOrder,
    q: T,
    workload: PbsWorkload,
) -> TfheParameters<T> {
    let modulus = BarrettModulus::new(q);
    let q_value: f64 = q.as_into();
    let t = T::as_from(workload.plaintext_modulus);
    let lwe = LweParameters::new(
        workload.lwe_dimension,
        t,
        modulus,
        SecretKeyDistr::UniformBinary,
        q_value * LWE_STD_DEV,
    );
    let glwe = GlweParameters::new(
        1,
        workload.poly_length,
        t,
        modulus,
        SecretKeyDistr::UniformBinary,
        (q_value * GLWE_STD_DEV).max(6.4),
    );
    let (pbs_base, pbs_level, ks_base, ks_level) = if T::BITS == 64 {
        (23, 1, 3, 5)
    } else {
        // Smaller digits limit accumulated key noise at the t=32 output scale.
        (5, 5, 2, 13)
    };
    TfheParameters::try_new(
        lwe,
        glwe,
        ApproxSignedBasis::new(Some(q), pbs_base, Some(pbs_level)),
        ApproxSignedBasis::new(Some(q), ks_base, Some(ks_level)),
        order,
    )
    .unwrap()
}
