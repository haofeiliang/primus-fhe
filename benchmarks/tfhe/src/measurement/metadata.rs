//! Opt-in per-case numerical evidence, emitted outside timed loops.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::Write,
    sync::{Mutex, OnceLock},
};

/// Measurement schema changes require a new baseline even if arithmetic is unchanged.
pub const VERSION: u32 = 2;

/// Decimal strings preserve native 2^64 and prime moduli without JSON float rounding.
fn modulus<T: FheUint, M: RingContext<T>>(modulus: M) -> String {
    modulus
        .explicit_value()
        .map_or_else(|| format!("2^{}", T::BITS), |q| q.to_string())
}

/// Record retained levels and discarded bits, not just the requested radix.
fn basis<T: FheUint>(basis: &ApproxSignedBasis<T>) -> Value {
    json!({"base_log": basis.log_basis().get(), "levels": basis.decompose_length().get(), "drop_bits": basis.drop_bits()})
}

/// Actual GLWE parameters, including both key-noise roles and return order.
pub fn glwe<T: FheUint, M: RingContext<T>>(p: &primus_tfhe_glwe::TfheParameters<T, M>) -> Value {
    let br = p.blind_rotation_ggsw();
    let ks = p.glwe_key_switching().output();
    json!({
        "word_bits": T::BITS, "q": modulus(p.cipher_modulus()), "Q": modulus(p.cipher_modulus()),
        "small_lwe_dimension": p.small_lwe().dimension().get(),
        "external_lwe_dimension": p.external_lwe_dimension().get(),
        "poly_length": br.poly_length().get(), "glwe_dimension": br.dimension().get(),
        "small_lwe_secret": format!("{:?}", p.small_lwe().secret_key_distr()),
        "ring_secret": format!("{:?}", br.secret_key_distr()),
        "small_lwe_sigma": p.small_lwe().noise_standard_deviation(),
        "br": {"basis": basis(br.basis()), "coefficient_sigma": br.noise_standard_deviation()},
        "ks": {"kind": "ring_glwe", "basis": basis(ks.basis()), "coefficient_sigma": ks.noise_standard_deviation()},
        "order": format!("{:?}", p.pbs_order())
    })
}

/// Actual NTRU parameters; external q and ring Q are independent domains.
pub fn ntru<T: FheUint, M: RingContext<T>, LM: RingContext<T>>(
    p: &primus_tfhe_ntru::TfheParameters<T, M, LM>,
) -> Value {
    let br = p.blind_rotation();
    let ring = p.accumulator_ntru();
    json!({
        "word_bits": T::BITS, "q": modulus(p.external_lwe().cipher_modulus()), "Q": modulus(ring.cipher_modulus()),
        "external_lwe_dimension": p.external_lwe_dimension().get(), "poly_length": p.poly_length().get(),
        "external_lwe_secret": format!("{:?}", p.external_lwe().secret_key_distr()),
        "ring_secret": format!("{:?}", ring.secret_key_distr()),
        "external_lwe_sigma": p.external_lwe().noise_standard_deviation(),
        "br": {"basis": basis(br.basis()), "coefficient_sigma": ring.noise_distribution().standard_deviation()},
        "ks": {"kind": "ntru_to_lwe_at_q", "basis": basis(p.key_switching_basis()), "coefficient_sigma": p.key_switching_lwe().noise_standard_deviation()},
        "order": "BootstrapModulusSwitchKeyswitch"
    })
}

/// CBS roles are independent of the PBS return key; null levels mean the full
/// modulus-dependent decomposition selected by the actual parameter constructor.
pub fn cbs(config: primus_tfhe::CircuitBootstrapConfig) -> Value {
    let decomposition = |d: primus_decompose::DecompositionConfig| {
        json!({
            "base_log": d.log_basis.get(), "levels": d.level_count.map(|l| l.get())
        })
    };
    json!({"output": decomposition(config.output),
        "trace": {"decomposition": decomposition(config.trace.decomposition), "coefficient_sigma": config.trace.noise_standard_deviation},
        "scheme_switch": {"decomposition": decomposition(config.scheme_switch.decomposition), "coefficient_sigma": config.scheme_switch.noise_standard_deviation}})
}

/// One complete sparse mapping; dense/classic uses no copies or buckets.
pub fn blind_rotation(sparse: bool) -> Value {
    match crate::benchmark::blind_rotation(sparse) {
        primus_tfhe::BlindRotationConfig::Sparse {
            copy_count,
            bucket_count,
        } => json!({"algorithm": "sparse", "copies": copy_count, "buckets": bucket_count}),
        primus_tfhe::BlindRotationConfig::Classic => json!({"algorithm": "classic"}),
    }
}

/// Writes once per executed case, never during a timed iteration or --list.
/// The runner supplies a fresh output path; direct Cargo runs need no metadata.
pub fn record(operation: &str, case: &super::Case<'_>, build: impl FnOnce() -> Value) {
    let Some(path) = std::env::var_os("PRIMUS_BENCH_METADATA") else {
        return;
    };
    let super::Case {
        family,
        engine,
        word_bits,
        workload,
    } = case;
    let id = case.full_id(operation);
    let uses_transform = !workload.contains("create_lut_and_drop");
    static RECORDED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    if !RECORDED
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(id.clone())
    {
        return;
    }
    let evidence = json!({
        "version": VERSION, "id": id,
        "operation": operation, "family": family, "engine": engine, "word": format!("u{word_bits}"),
        "security": "unassessed", "dfr": "unassessed", "workload": workload,
        "fixture_lifetime": if uses_transform && operation != "setup" { "owned keys/input cached; evaluator/output recreated per callback; reused per iteration" } else { "construction or stage diagnostic; see case timing contract" },
        "fft_plan": if uses_transform && *engine == "tfhe_fft" { "runtime Measure(10ms); algorithm not exposed" } else if uses_transform && *engine == "rustfft" { "RustFFT planner; algorithm not exposed" } else { "not applicable" },
        "configuration": build(),
    });
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open benchmark metadata");
    writeln!(output, "{evidence}").expect("write benchmark metadata");
}

/// Identifies the observed Fourier permutation, not the planner's private kernel.
/// A changed layout invalidates strict pairing; an equal layout does not prove
/// equal FFT algorithms. Store this limitation alongside every Fourier result.
#[cfg(any(feature = "glwe-fourier", feature = "ntru-fourier"))]
pub fn fft_layout(table: &impl primus_fft::FftTable) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for (source, conjugate) in table.automorphism_map(5) {
        for byte in (source as u64)
            .to_le_bytes()
            .into_iter()
            .chain([u8::from(conjugate)])
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
    }
    format!("fnv1a64:{hash:016x}")
}
