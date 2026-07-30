use primus_distr::{sample_crt_gaussian_values_to, sample_crt_uniform_values_to};
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::DcrtPolynomial;
use primus_reduce::FieldContext;
use primus_rns::HybridRNS;
use rand::distr::Uniform;

use super::HybridRnsGlweKeySwitchingKey;
use crate::glwe::secret_key::encode_secret_coefficient;
use crate::{CrtGlweParameters, DcrtGlweSecretKey, GlweSecretKey};

impl<T: FheUint> HybridRnsGlweKeySwitchingKey<T> {
    /// Generates a hybrid-RNS key-switching key in the NTT domain over `QP`.
    pub fn generate<R, M, QpTable>(
        input_secret_key: &GlweSecretKey<T>,
        input_parameters: &CrtGlweParameters<T, M>,
        output_secret_key: &GlweSecretKey<T>,
        hybrid_parameters: &HybridRNS<T, M>,
        qp_table: &QpTable,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        QpTable: DcrtTable<ValueT = T>,
    {
        let poly_length = input_parameters.poly_length();
        let qp_moduli = hybrid_parameters.qp_base().moduli();
        assert_eq!(input_secret_key.dimension(), input_parameters.dimension());
        assert_eq!(input_secret_key.poly_length(), poly_length);
        assert_eq!(output_secret_key.poly_length(), poly_length);
        assert_eq!(qp_table.poly_length(), poly_length);
        assert_eq!(qp_table.moduli_count(), hybrid_parameters.qp_moduli_count());
        assert!(
            input_parameters
                .cipher_moduli()
                .iter()
                .zip(hybrid_parameters.q_base().moduli())
                .all(|(input_modulus, hybrid_modulus)| input_modulus.value()
                    == hybrid_modulus.value())
        );
        assert!(
            qp_table
                .ntt_tables()
                .iter()
                .zip(qp_moduli)
                .all(|(ntt_table, modulus)| ntt_table.modulus() == modulus.value())
        );

        let qp_moduli_values: Vec<T> = qp_moduli.iter().map(|modulus| modulus.value()).collect();
        let p_mod_q = hybrid_parameters.p_mod_q();
        let partition_count = hybrid_parameters.partition_count();
        let input_dimension = input_secret_key.dimension();
        let output_dimension = output_secret_key.dimension();
        let qp_moduli_count =
            hybrid_parameters.q_moduli_count() + hybrid_parameters.p_moduli_count();
        let qp_uniform_distributions: Vec<Uniform<T>> = qp_moduli_values
            .iter()
            .map(|&modulus| Uniform::new(T::ZERO, modulus).expect("the QP moduli must be nonzero"))
            .collect();

        let output_secret_key_qp =
            DcrtGlweSecretKey::from_coeff_secret_key(output_secret_key, qp_table);
        let output_secret_key_qp = output_secret_key_qp.key();
        let noise_distribution = input_parameters.noise_distribution().clone();
        let qp_rns_poly_len = poly_length * qp_moduli_count;
        let qp_rns_glwe_len = (output_dimension + 1) * qp_rns_poly_len;
        let qp_rns_gadget_len = partition_count * qp_rns_glwe_len;
        let mut key = vec![T::ZERO; input_dimension * qp_rns_gadget_len];

        for (secret_polynomial, key_for_secret) in input_secret_key
            .iter()
            .zip(key.chunks_exact_mut(qp_rns_gadget_len))
        {
            for (partition, key_entry) in hybrid_parameters
                .partitions()
                .zip(key_for_secret.chunks_exact_mut(qp_rns_glwe_len))
            {
                let (mask, body) = key_entry.split_at_mut(output_dimension * qp_rns_poly_len);
                sample_crt_gaussian_values_to(
                    body,
                    poly_length,
                    &qp_moduli_values,
                    &noise_distribution,
                    rng,
                );

                let q_range = partition.q_range();
                let partition_elements = q_range.start * poly_length..q_range.end * poly_length;
                for ((body_limb, modulus), &scalar) in body[partition_elements]
                    .chunks_exact_mut(poly_length)
                    .zip(&qp_moduli[q_range])
                    .zip(&p_mod_q[q_range])
                {
                    let modulus_value = modulus.value();
                    for (body_coefficient, &secret_coefficient) in
                        body_limb.iter_mut().zip(secret_polynomial)
                    {
                        let secret_residue =
                            encode_secret_coefficient::<T>(secret_coefficient, modulus_value);
                        *body_coefficient = modulus.reduce_add(
                            *body_coefficient,
                            modulus.reduce_mul(scalar, secret_residue),
                        );
                    }
                }

                qp_table.transform_slice(body);
                let mut body = DcrtPolynomial(body);
                for (mask_polynomial, output_secret_polynomial) in mask
                    .chunks_exact_mut(qp_rns_poly_len)
                    .zip(output_secret_key_qp.chunks_exact(qp_rns_poly_len))
                {
                    sample_crt_uniform_values_to(
                        mask_polynomial,
                        poly_length,
                        &qp_uniform_distributions,
                        rng,
                    );
                    body.add_mul_assign(
                        &DcrtPolynomial(mask_polynomial),
                        &DcrtPolynomial(output_secret_polynomial),
                        poly_length,
                        qp_moduli,
                    );
                }
            }
        }

        Self {
            key,
            poly_length,
            qp_rns_poly_len,
            qp_rns_glwe_len,
            qp_rns_gadget_len,
            partition_count,
            input_rns_poly_len: input_parameters.rns_poly_len(),
            output_dimension,
        }
    }
}
