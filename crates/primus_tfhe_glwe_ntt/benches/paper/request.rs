//! The benchmark's q -> Q -> q adapter, distinct from the public evaluator.

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_lwe::{LweCiphertext, LweDimension, LweParameters, LweSecretKey};
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntt::MonomialNttTable;
use primus_reduce::{
    Modulus, ModulusSwitch, PrepareModulusSwitch, ReduceAdd, ReduceAddAssign, ReduceSub,
};
use primus_tfhe::{LookupTable, rotation::RotationModulusSwitch};
use primus_tfhe_glwe_ntt::{ClientKey, Evaluator, ServerKey, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

use super::parameters::{Case, Mode};

/// Fixed input and reusable buffers; input/output use q, lifted/returned use Q.
/// Prepared switches make the adapter allocation-free during each request.
pub(super) struct Request<T: FheUint> {
    input: LweCiphertext<T>,
    rhs: Option<LweCiphertext<T>>,
    pub lifted: LweCiphertext<T>,
    returned: LweCiphertext<T>,
    output: LweCiphertext<T>,
    pub lut: LookupTable<T>,
    lift: ModulusSwitch<T>,
    lower: ModulusSwitch<T>,
    input_modulus: PowOf2Modulus<T>,
    ring_modulus: BarrettModulus<T>,
    output_bias: T,
}

impl<T: FheUint> Request<T> {
    /// Prepare public LUT/conversions and allocate outputs. Validation below
    /// supplies the actual encrypted benchmark input before any timing starts.
    pub fn new<Table: MonomialNttTable<ValueT = T>>(
        context: &TfheContext<T, Table>,
        case: Case,
    ) -> Self {
        let modulus = context.parameters().cipher_modulus();
        let q = PowOf2Modulus::new(T::as_from(case.lwe_modulus));
        let is_gate = case.plaintext_modulus == 4;
        // Match OpenFHE's floor(Q/8)+1 internal scale. The LUT is positive
        // at sums 0 and 1; its negacyclic extension is negative at sum 2.
        // Adding the positive bias after PBS restores the Boolean output.
        let output_bias = if is_gate {
            T::as_from(case.ring_modulus / 8 + 1)
        } else {
            T::ZERO
        };
        let lut = if is_gate {
            LookupTable::try_new(
                2,
                context.parameters().blind_rotation_ggsw().poly_length(),
                T::as_from(4u32),
                modulus,
                modulus,
                |_| Ok(output_bias),
            )
            .unwrap()
        } else {
            let codec = RoundedCodec::new(T::as_from(case.plaintext_modulus), modulus);
            context
                .parameters()
                .lookup_table_compiler(&codec)
                .unwrap()
                .compile_fn(|m| T::as_from(case.function(m)))
                .unwrap()
        };
        Self {
            input: context.allocate_lwe_ciphertext(),
            rhs: is_gate.then(|| context.allocate_lwe_ciphertext()),
            lifted: context.allocate_lwe_ciphertext(),
            returned: context.allocate_lwe_ciphertext(),
            output: context.allocate_lwe_ciphertext(),
            lut,
            lift: q.prepare_switch_to(modulus),
            lower: modulus.prepare_switch_to(q),
            input_modulus: q,
            ring_modulus: modulus,
            output_bias,
        }
    }

    pub fn lift_input(&mut self) {
        if let Some(rhs) = &self.rhs {
            // Sum the two independently encrypted Boolean inputs at q before
            // lifting. This public affine operation belongs to NAND's timer.
            let sum = self
                .input
                .as_ref()
                .iter()
                .zip(rhs.as_ref())
                .map(|(&lhs, &rhs)| self.input_modulus.reduce_add(lhs, rhs));
            self.lift
                .switch_map(sum.zip(self.lifted.as_mut()), |x, out| *out = x);
        } else {
            switch_to(self.lift, &self.input, &mut self.lifted);
        }
    }

    /// One complete adapted request, including both coefficient conversions.
    pub fn evaluate<Table: MonomialNttTable<ValueT = T>>(
        &mut self,
        evaluator: &mut Evaluator<'_, T, Table>,
    ) {
        self.lift_input();
        evaluator.apply_lookup_table_to(
            self.lifted.as_view(),
            &self.lut,
            self.returned.as_mut_view(),
        );
        self.ring_modulus
            .reduce_add_assign(self.returned.b_mut(), self.output_bias);
        switch_to(self.lower, &self.returned, &mut self.output);
    }

    /// Check all messages using two independent input RNGs. This is a finite
    /// numerical diagnostic, not a failure-probability or security estimate.
    pub fn validate<Table: MonomialNttTable<ValueT = T>>(
        &mut self,
        context: &TfheContext<T, Table>,
        client: &ClientKey<T>,
        server: &ServerKey<T>,
        case: Case,
        mode: Mode,
        name: &str,
    ) {
        let q = PowOf2Modulus::new(T::as_from(case.lwe_modulus));
        let external = LweParameters::new(
            LweDimension::new(case.dimension(mode)),
            T::as_from(case.plaintext_modulus),
            q,
            case.secret(mode),
            3.19,
        );
        let secret = external_secret(client, q);
        let mut evaluator = context.evaluator(server).unwrap();
        let mut max_error = T::ZERO;
        let messages: Vec<_> = if self.rhs.is_some() {
            vec![
                (0, Some(0), 1),
                (0, Some(1), 1),
                (1, Some(0), 1),
                (1, Some(1), 0),
            ]
        } else {
            (0..case.plaintext_modulus as usize / 2)
                .map(|m| (m, None, case.function(m)))
                .collect()
        };
        for seed in [43, 4343] {
            let mut rng = StdRng::seed_from_u64(seed);
            for &(m, rhs, expected) in &messages {
                secret.encrypt_to(T::as_from(m), &mut self.input, &external, &mut rng);
                if let Some(rhs) = rhs {
                    secret.encrypt_to(
                        T::as_from(rhs),
                        self.rhs.as_mut().unwrap(),
                        &external,
                        &mut rng,
                    );
                }
                self.evaluate(&mut evaluator);
                self.check_lifted_exponents(case);
                let expected = T::as_from(expected);
                assert_eq!(
                    secret.decrypt(&self.output, &external),
                    expected,
                    "{name}, seed={seed}, m={m}, rhs={rhs:?}"
                );
                let phase = secret.as_view().decrypt_phase(&self.output, q);
                let encoded = external
                    .plaintext_codec()
                    .encode_value(expected, PlaintextEmbedding::Unsigned);
                let error = q.reduce_sub(phase, encoded);
                max_error = max_error.max(error.min(q.reduce_sub(T::ZERO, error)));
            }
        }
        // Restore the same nonzero request for every timing stage/algorithm.
        let mut rng = StdRng::seed_from_u64(43);
        secret.encrypt_to(T::ONE, &mut self.input, &external, &mut rng);
        if let Some(rhs) = &mut self.rhs {
            secret.encrypt_to(T::ONE, rhs, &external, &mut rng);
        }
        let (_, allocation) = primus_test_allocations::measure(|| self.evaluate(&mut evaluator));
        assert_eq!(allocation.count, 0, "{name}: online allocation");

        let gadget = context.parameters().blind_rotation_ggsw();
        let levels = gadget.basis().decompose_length().get();
        let controls = match mode {
            Mode::DenseClassic => 2 * case.dense_dimension,
            Mode::FixedWeightClassic => case.sparse_dimension,
            Mode::Sparse | Mode::SparseCandidate => {
                let (copies, buckets) = mode.sparse_counts(case).unwrap();
                copies * case.sparse_dimension + buckets
            }
        };
        let key_bytes = controls * gadget.ggsw_len() * size_of::<T>();
        eprintln!(
            "paper_profile,{name},Q={},q={},br_base_log={},br_levels={levels},br_coefficient_bytes={key_bytes},max_error_q={max_error},bootstrap_count=1,return=ring_ks_at_Q,online_allocations=0",
            case.ring_modulus, case.lwe_modulus, case.br_base_log,
        );
    }

    /// q divides 2N: lifting must preserve the exact public exponent a*(2N/q).
    /// For NAND, a is the sum of the two input coefficients modulo q.
    fn check_lifted_exponents(&self, case: Case) {
        let rotation = RotationModulusSwitch::new(self.ring_modulus, 2 * case.poly_length, 1);
        for (i, (&a, &lifted)) in self
            .input
            .as_ref()
            .iter()
            .zip(self.lifted.as_ref())
            .enumerate()
        {
            let a = self
                .rhs
                .as_ref()
                .map_or(a, |rhs| self.input_modulus.reduce_add(a, rhs.as_ref()[i]));
            let a: usize = a.as_into();
            assert_eq!(
                rotation.exponent(lifted),
                a * (2 * case.poly_length / case.lwe_modulus as usize)
            );
        }
    }
}

/// Conversion selects its arithmetic kernel once for the whole ciphertext.
fn switch_to<T: FheUint>(
    switch: ModulusSwitch<T>,
    input: &LweCiphertext<T>,
    output: &mut LweCiphertext<T>,
) {
    switch.switch_map(
        input.as_ref().iter().copied().zip(output.as_mut()),
        |x, out| *out = x,
    );
}

/// Re-encode the same small secret at q. Modulus switching a secret would scale
/// its coefficients and is not the operation wanted here.
fn external_secret<T: FheUint>(client: &ClientKey<T>, q: PowOf2Modulus<T>) -> LweSecretKey<T> {
    let secret = client.small_lwe_secret_key();
    let coefficients = secret
        .as_ref()
        .iter()
        .map(|&x| {
            if x <= T::ONE {
                x
            } else {
                assert_eq!(x, secret.cipher_modulus_minus_one());
                q.minus_one()
            }
        })
        .collect();
    LweSecretKey::new(coefficients, secret.distr(), q)
}
