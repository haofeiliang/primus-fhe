//! Experimental NTRU TFHE parameter validation.

use std::{
    hint::black_box,
    mem::size_of,
    time::{Duration, Instant},
};

use clap::{Args, ValueEnum};
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_fhe_core::{SecretCoefficient, plaintext::PlaintextEmbedding};
use primus_lattice::{MAX_POLY_LENGTH, MIN_POLY_LENGTH};
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_ntt::{NttTable, U32NttTable};
use primus_reduce::RingContext;
use primus_tfhe::{Ciphertext, LookupTable};
use primus_tfhe_ntru::NtruTfheParameters;
use rand::{RngExt, SeedableRng, rngs::StdRng};

const DEFAULT_NTT_MODULUS: u32 = 132_120_577;
const DEFAULT_SEED: u64 = 0x4e54_5255_5041_5241;

/// Executes one NTRU parameter validation command.
pub(crate) fn run(config: Config) -> Result<(), String> {
    config.validate()?;

    match config.backend {
        Backend::Ntt => run_ntt(&config),
        Backend::Fourier => run_fourier(&config),
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Ntt,
    Fourier,
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            Self::Ntt => "ntt",
            Self::Fourier => "fourier",
        }
    }
}

/// Command-line parameters for one NTRU TFHE validation run.
#[derive(Args)]
pub(crate) struct Config {
    /// Backend to validate.
    #[arg(long, value_enum, default_value_t = Backend::Ntt)]
    backend: Backend,
    /// NTRU polynomial length.
    #[arg(long, default_value_t = 1024)]
    poly_length: usize,
    /// Active external LWE secret length.
    #[arg(long, default_value_t = 800)]
    lwe_dimension: usize,
    /// Number of measured PBS calls.
    #[arg(long, default_value_t = 100)]
    trials: usize,
    /// Number of unmeasured PBS warmup calls.
    #[arg(long, default_value_t = 3)]
    warmup: usize,
    /// Deterministic random seed.
    #[arg(long, default_value_t = DEFAULT_SEED)]
    seed: u64,
    /// Plaintext modulus.
    #[arg(long, default_value_t = 4)]
    plain_modulus: u32,
    /// Standard deviation of fresh error coefficients.
    #[arg(long, default_value_t = 0.7)]
    noise_standard_deviation: f64,
    /// Explicit modulus used by the NTT backend.
    #[arg(long, default_value_t = DEFAULT_NTT_MODULUS)]
    ntt_modulus: u32,
    /// Base-two logarithm of the bootstrapping decomposition basis.
    #[arg(long, default_value_t = 9)]
    bootstrapping_log_basis: u32,
    /// Number of bootstrapping decomposition levels.
    #[arg(long, default_value_t = 3)]
    bootstrapping_levels: usize,
    /// Base-two logarithm of the key-switching decomposition basis.
    #[arg(long, default_value_t = 9)]
    key_switching_log_basis: u32,
    /// Number of key-switching decomposition levels.
    #[arg(long, default_value_t = 3)]
    key_switching_levels: usize,
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if !(MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&self.poly_length)
            || !self.poly_length.is_power_of_two()
        {
            return Err(format!(
                "--poly-length must be a power of two in {MIN_POLY_LENGTH}..={MAX_POLY_LENGTH}"
            ));
        }
        if !(1..=self.poly_length).contains(&self.lwe_dimension) {
            return Err("--lwe-dimension must belong to 1..=poly-length".into());
        }
        if self.trials == 0 {
            return Err("--trials must be greater than zero".into());
        }
        if self.plain_modulus < 4 || !self.plain_modulus.is_multiple_of(2) {
            return Err("--plain-modulus must be even and at least four".into());
        }
        if !self.noise_standard_deviation.is_finite() || self.noise_standard_deviation <= 0.0 {
            return Err("--noise-standard-deviation must be finite and positive".into());
        }
        if self.bootstrapping_log_basis < 2 || self.key_switching_log_basis < 2 {
            return Err("decomposition log basis must be at least two".into());
        }
        if self.bootstrapping_levels == 0 || self.key_switching_levels == 0 {
            return Err("decomposition level counts must be greater than zero".into());
        }
        if matches!(self.backend, Backend::Ntt) && self.ntt_modulus <= self.plain_modulus {
            return Err("--ntt-modulus must be greater than --plain-modulus".into());
        }
        Ok(())
    }

    fn programmable_domain_len(&self) -> usize {
        (self.plain_modulus / 2) as usize
    }
}

fn run_ntt(config: &Config) -> Result<(), String> {
    let modulus = BarrettModulus::new(config.ntt_modulus);
    let external_lwe = LweParameters::new(
        config.lwe_dimension,
        config.plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        config.noise_standard_deviation,
    );
    let accumulator = NtruParameters::new(
        config.poly_length,
        config.plain_modulus,
        modulus,
        SecretKeyDistr::SparseTernary,
        config.noise_standard_deviation,
    );
    let client = NtruParameters::new(
        config.poly_length,
        config.plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        config.noise_standard_deviation,
    );
    let parameters = make_parameters(config, external_lwe, &accumulator, &client)?;
    let table = U32NttTable::new(config.poly_length.trailing_zeros(), modulus)
        .map_err(|error| format!("failed to create NTT table: {error}"))?;
    let context = primus_tfhe_ntru_ntt::TfheContext::try_new(parameters, table)
        .map_err(|error| format!("failed to create NTT TFHE context: {error}"))?;

    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut key_generator = primus_tfhe_ntru_ntt::KeyGenerator::new(&context);
    let client_started = Instant::now();
    let client_key = key_generator
        .generate_client_key(&mut rng)
        .map_err(|error| format!("failed to generate NTT client key: {error}"))?;
    let client_key_time = client_started.elapsed();
    let server_started = Instant::now();
    let server_key = key_generator
        .try_generate_server_key(&client_key, &mut rng)
        .map_err(|error| format!("failed to generate NTT server key: {error}"))?;
    let server_key_time = server_started.elapsed();

    let lookup_table =
        make_lookup_table(config, |function| context.compile_lookup_table_fn(function))?;
    let encryptor = context
        .encryptor(&client_key)
        .map_err(|error| format!("failed to create NTT encryptor: {error}"))?;
    let mut evaluator = context
        .evaluator(&server_key)
        .map_err(|error| format!("failed to create NTT evaluator: {error}"))?;
    let pbs = measure_pbs(
        config,
        &mut rng,
        &lookup_table,
        |message, rng| {
            encryptor
                .encrypt_padded(message, rng)
                .map_err(|error| error.to_string())
        },
        |input, lookup_table, output| {
            evaluator.apply_lookup_table_to(input, lookup_table, output);
        },
        |output, expected| {
            measure_output(
                output,
                expected,
                client_key.external_lwe_secret_key(),
                context.parameters().external_lwe(),
            )
        },
    )?;

    let report = Report {
        backend: Backend::Ntt,
        client_key_time,
        server_key_time,
        server_key_bytes: server_key_bytes(config, config.poly_length, size_of::<u32>())?,
        client_shape: KeyShape::from_coefficients(client_key.external_lwe_secret_key()),
        accumulator_shape: KeyShape::from_coefficients(
            client_key.accumulator_ntru_secret_key().as_slice(),
        ),
        decoding_margin: decoding_margin(context.parameters().external_lwe()),
        pbs,
        client_spectrum: None,
        accumulator_spectrum: None,
    };
    report.print(config);
    Ok(())
}

fn run_fourier(config: &Config) -> Result<(), String> {
    let modulus = NativeModulus::new();
    let external_lwe = LweParameters::new(
        config.lwe_dimension,
        config.plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        config.noise_standard_deviation,
    );
    let accumulator = NtruParameters::new(
        config.poly_length,
        config.plain_modulus,
        modulus,
        SecretKeyDistr::SparseTernary,
        config.noise_standard_deviation,
    );
    let client = NtruParameters::new(
        config.poly_length,
        config.plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        config.noise_standard_deviation,
    );
    let parameters = make_parameters(config, external_lwe, &accumulator, &client)?;
    let table = RustFftTable::new(config.poly_length.trailing_zeros())
        .map_err(|error| format!("failed to create Fourier table: {error}"))?;
    let context = primus_tfhe_ntru_fourier::TfheContext::try_new(parameters, table)
        .map_err(|error| format!("failed to create Fourier TFHE context: {error}"))?;

    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut key_generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);
    let client_started = Instant::now();
    let client_key = key_generator
        .generate_client_key(&mut rng)
        .map_err(|error| format!("failed to generate Fourier client key: {error}"))?;
    let client_key_time = client_started.elapsed();
    let server_started = Instant::now();
    let server_key = key_generator
        .try_generate_server_key(&client_key, &mut rng)
        .map_err(|error| format!("failed to generate Fourier server key: {error}"))?;
    let server_key_time = server_started.elapsed();

    let client_spectrum = spectrum(
        client_key.client_ntru_secret_key(),
        &mut context.new_fft_engine(),
    );
    let accumulator_spectrum = spectrum(
        client_key.accumulator_ntru_secret_key(),
        &mut context.new_fft_engine(),
    );
    let lookup_table =
        make_lookup_table(config, |function| context.compile_lookup_table_fn(function))?;
    let encryptor = context
        .encryptor(&client_key)
        .map_err(|error| format!("failed to create Fourier encryptor: {error}"))?;
    let mut evaluator = context
        .evaluator(&server_key)
        .map_err(|error| format!("failed to create Fourier evaluator: {error}"))?;
    let pbs = measure_pbs(
        config,
        &mut rng,
        &lookup_table,
        |message, rng| {
            encryptor
                .encrypt_padded(message, rng)
                .map_err(|error| error.to_string())
        },
        |input, lookup_table, output| {
            evaluator.apply_lookup_table_to(input, lookup_table, output);
        },
        |output, expected| {
            measure_output(
                output,
                expected,
                client_key.external_lwe_secret_key(),
                context.parameters().external_lwe(),
            )
        },
    )?;

    let report = Report {
        backend: Backend::Fourier,
        client_key_time,
        server_key_time,
        server_key_bytes: server_key_bytes(config, config.poly_length / 2, size_of::<Complex64>())?,
        client_shape: KeyShape::from_coefficients(client_key.external_lwe_secret_key()),
        accumulator_shape: KeyShape::from_coefficients(
            client_key.accumulator_ntru_secret_key().as_slice(),
        ),
        decoding_margin: decoding_margin(context.parameters().external_lwe()),
        pbs,
        client_spectrum: Some(client_spectrum),
        accumulator_spectrum: Some(accumulator_spectrum),
    };
    report.print(config);
    Ok(())
}

fn make_parameters<M>(
    config: &Config,
    external_lwe: LweParameters<u32, M>,
    accumulator: &NtruParameters<u32, M>,
    client: &NtruParameters<u32, M>,
) -> Result<NtruTfheParameters<u32, M>, String>
where
    M: RingContext<u32>,
{
    let bootstrapping = NlevParameters::try_with_ntru_params(
        accumulator,
        config.bootstrapping_log_basis,
        Some(config.bootstrapping_levels),
    )
    .map_err(|error| format!("invalid bootstrapping decomposition: {error}"))?;
    let key_switching = NlevParameters::try_with_ntru_params(
        client,
        config.key_switching_log_basis,
        Some(config.key_switching_levels),
    )
    .map_err(|error| format!("invalid key-switching decomposition: {error}"))?;
    NtruTfheParameters::try_new(external_lwe, bootstrapping, key_switching)
        .map_err(|error| format!("invalid NTRU TFHE parameters: {error}"))
}

fn make_lookup_table<E>(
    config: &Config,
    compile: impl FnOnce(Box<dyn Fn(usize) -> u32>) -> Result<LookupTable<u32>, E>,
) -> Result<LookupTable<u32>, String>
where
    E: ToString,
{
    let domain_len = config.programmable_domain_len();
    compile(Box::new(move |input| {
        ((input as u64 * 3 + 1) % domain_len as u64) as u32
    }))
    .map_err(|error| format!("failed to compile lookup table: {}", error.to_string()))
}

fn lut_output(input: u32, domain_len: usize) -> u32 {
    ((input as u64 * 3 + 1) % domain_len as u64) as u32
}

fn measure_pbs<Encrypt, Evaluate, Measure>(
    config: &Config,
    rng: &mut StdRng,
    lookup_table: &LookupTable<u32>,
    mut encrypt: Encrypt,
    mut evaluate: Evaluate,
    mut measure: Measure,
) -> Result<PbsStats, String>
where
    Encrypt: FnMut(u32, &mut StdRng) -> Result<Ciphertext<u32>, String>,
    Evaluate: FnMut(&Ciphertext<u32>, &LookupTable<u32>, &mut Ciphertext<u32>),
    Measure: FnMut(&Ciphertext<u32>, u32) -> OutputMeasurement,
{
    let domain_len = config.programmable_domain_len();
    let cold_input = encrypt(0, rng)?;
    let mut output = cold_input.clone();
    let started = Instant::now();
    evaluate(
        black_box(&cold_input),
        black_box(lookup_table),
        black_box(&mut output),
    );
    let cold = started.elapsed();

    for index in 0..config.warmup {
        let message = (index % domain_len) as u32;
        let input = encrypt(message, rng)?;
        evaluate(&input, lookup_table, &mut output);
    }

    let mut durations = Vec::with_capacity(config.trials);
    let mut noises = Vec::with_capacity(config.trials);
    let mut failures = 0;
    for _ in 0..config.trials {
        let message = rng.random_range(0..domain_len) as u32;
        let expected = lut_output(message, domain_len);
        let input = encrypt(message, rng)?;
        let started = Instant::now();
        evaluate(
            black_box(&input),
            black_box(lookup_table),
            black_box(&mut output),
        );
        durations.push(started.elapsed());

        let measurement = measure(&output, expected);
        failures += usize::from(measurement.decoded != expected);
        noises.push(measurement.noise);
    }
    durations.sort_unstable();
    noises.sort_unstable();

    Ok(PbsStats {
        cold,
        minimum: durations[0],
        p50: percentile(&durations, 50),
        p95: percentile(&durations, 95),
        maximum: *durations.last().expect("non-empty validation durations"),
        noise_p50: percentile(&noises, 50),
        noise_p95: percentile(&noises, 95),
        noise_p99: percentile(&noises, 99),
        noise_maximum: *noises.last().expect("non-empty validation noises"),
        failures,
    })
}

fn measure_output<M>(
    ciphertext: &Ciphertext<u32>,
    expected: u32,
    secret_key: &[SecretCoefficient<u32>],
    parameters: &LweParameters<u32, M>,
) -> OutputMeasurement
where
    M: RingContext<u32>,
{
    let modulus = parameters.cipher_modulus();
    let (mask, body) = ciphertext.as_lwe().a_b();
    let dot_product = modulus.reduce_dot_product_iter(
        mask.iter().copied(),
        secret_key
            .iter()
            .copied()
            .map(|coefficient| encode_secret(coefficient, modulus)),
    );
    let phase = modulus.reduce_sub(body, dot_product);
    let decoded = parameters.plaintext_codec().decode_value(phase);
    let expected_encoding = parameters
        .plaintext_codec()
        .encode_value(expected, PlaintextEmbedding::Unsigned);
    let noise = modulus
        .reduce_sub(phase, expected_encoding)
        .min(modulus.reduce_sub(expected_encoding, phase));
    OutputMeasurement { decoded, noise }
}

fn encode_secret<M>(coefficient: SecretCoefficient<u32>, modulus: M) -> u32
where
    M: RingContext<u32>,
{
    if coefficient < 0 {
        modulus.reduce_neg(modulus.reduce(coefficient.wrapping_neg() as u32))
    } else {
        modulus.reduce(coefficient as u32)
    }
}

/// Returns half the smallest cyclic distance between adjacent plaintext encodings.
fn decoding_margin<M>(parameters: &LweParameters<u32, M>) -> u32
where
    M: RingContext<u32>,
{
    let modulus = parameters.cipher_modulus();
    let codec = parameters.plaintext_codec();
    let plain_modulus = parameters.plain_modulus_value();
    let mut minimum_spacing = u32::MAX;
    for message in 0..plain_modulus {
        let next = if message + 1 == plain_modulus {
            0
        } else {
            message + 1
        };
        let encoded = codec.encode_value(message, PlaintextEmbedding::Unsigned);
        let next_encoded = codec.encode_value(next, PlaintextEmbedding::Unsigned);
        minimum_spacing = minimum_spacing.min(modulus.reduce_sub(next_encoded, encoded));
    }
    minimum_spacing / 2
}

fn server_key_bytes(
    config: &Config,
    values_per_polynomial: usize,
    value_size: usize,
) -> Result<usize, String> {
    let bootstrapping_entries = config
        .lwe_dimension
        .checked_add(1)
        .and_then(|count| count.checked_mul(config.bootstrapping_levels))
        .ok_or("server-key element count overflow")?;
    let levels = bootstrapping_entries
        .checked_add(config.key_switching_levels)
        .ok_or("server-key element count overflow")?;
    values_per_polynomial
        .checked_mul(levels)
        .and_then(|count| count.checked_mul(value_size))
        .ok_or_else(|| "server-key byte count overflow".into())
}

fn spectrum<Table>(secret_key: &NtruSecretKey<u32>, fft: &mut FftEngine<'_, Table>) -> SpectrumStats
where
    Table: FftTable,
{
    let coefficients: Vec<u32> = secret_key
        .as_slice()
        .iter()
        .map(|&coefficient| coefficient as u32)
        .collect();
    let mut values = vec![Complex64::default(); fft.fourier_length()];
    fft.forward_as_integer(&coefficients, &mut values);

    let mut minimum_norm_squared = f64::INFINITY;
    let mut maximum_inverse_norm = 0.0f64;
    let mut maximum_inverse_residual = 0.0f64;
    for value in values {
        let norm_squared = value.norm_sqr();
        minimum_norm_squared = minimum_norm_squared.min(norm_squared);
        let inverse = Complex64::new(1.0, 0.0) / value;
        maximum_inverse_norm = maximum_inverse_norm.max(inverse.norm());
        maximum_inverse_residual =
            maximum_inverse_residual.max((value * inverse - Complex64::new(1.0, 0.0)).norm());
    }
    SpectrumStats {
        minimum_norm_squared,
        maximum_inverse_norm,
        maximum_inverse_residual,
    }
}

#[derive(Clone, Copy)]
struct OutputMeasurement {
    decoded: u32,
    noise: u32,
}

struct PbsStats {
    cold: Duration,
    minimum: Duration,
    p50: Duration,
    p95: Duration,
    maximum: Duration,
    noise_p50: u32,
    noise_p95: u32,
    noise_p99: u32,
    noise_maximum: u32,
    failures: usize,
}

struct SpectrumStats {
    minimum_norm_squared: f64,
    maximum_inverse_norm: f64,
    maximum_inverse_residual: f64,
}

struct KeyShape {
    negative_ones: usize,
    zeros: usize,
    ones: usize,
    other: usize,
}

impl KeyShape {
    fn from_coefficients(coefficients: &[SecretCoefficient<u32>]) -> Self {
        let mut shape = Self {
            negative_ones: 0,
            zeros: 0,
            ones: 0,
            other: 0,
        };
        for &coefficient in coefficients {
            match coefficient {
                -1 => shape.negative_ones += 1,
                0 => shape.zeros += 1,
                1 => shape.ones += 1,
                _ => shape.other += 1,
            }
        }
        shape
    }

    fn print(&self, label: &str) {
        println!(
            "{label}: -1={}, 0={}, 1={}, other={}",
            self.negative_ones, self.zeros, self.ones, self.other
        );
    }
}

struct Report {
    backend: Backend,
    client_key_time: Duration,
    server_key_time: Duration,
    server_key_bytes: usize,
    client_shape: KeyShape,
    accumulator_shape: KeyShape,
    decoding_margin: u32,
    pbs: PbsStats,
    client_spectrum: Option<SpectrumStats>,
    accumulator_spectrum: Option<SpectrumStats>,
}

impl Report {
    fn print(&self, config: &Config) {
        println!("NTRU TFHE parameter validation");
        println!("backend: {}", self.backend.name());
        println!(
            "N={}, n={}, t={}, sigma={}",
            config.poly_length,
            config.lwe_dimension,
            config.plain_modulus,
            config.noise_standard_deviation
        );
        match self.backend {
            Backend::Ntt => println!("q={}", config.ntt_modulus),
            Backend::Fourier => println!("q=2^32 (native)"),
        }
        println!(
            "bootstrapping: logB={}, L={}",
            config.bootstrapping_log_basis, config.bootstrapping_levels
        );
        println!(
            "key switching: logB={}, L={}",
            config.key_switching_log_basis, config.key_switching_levels
        );
        println!("seed=0x{:016x}", config.seed);
        println!();
        println!(
            "client-key generation (split API): {}",
            format_duration(self.client_key_time)
        );
        println!(
            "server-key generation (split API): {}",
            format_duration(self.server_key_time)
        );
        println!(
            "split key generation total: {}",
            format_duration(self.client_key_time + self.server_key_time)
        );
        println!(
            "server-key data: {} bytes ({:.3} MiB)",
            self.server_key_bytes,
            self.server_key_bytes as f64 / (1024.0 * 1024.0)
        );
        self.client_shape.print("active client secret");
        println!(
            "known zero padding: {}",
            config.poly_length - config.lwe_dimension
        );
        self.accumulator_shape.print("accumulator secret");
        if let Some(spectrum) = &self.client_spectrum {
            spectrum.print("client Fourier spectrum");
        }
        if let Some(spectrum) = &self.accumulator_spectrum {
            spectrum.print("accumulator Fourier spectrum");
        }
        println!();
        println!("PBS cold: {}", format_duration(self.pbs.cold));
        println!(
            "PBS warm: min={}, p50={}, p95={}, max={}",
            format_duration(self.pbs.minimum),
            format_duration(self.pbs.p50),
            format_duration(self.pbs.p95),
            format_duration(self.pbs.maximum)
        );
        println!(
            "noise: p50={}, p95={}, p99={}, max={}",
            self.pbs.noise_p50, self.pbs.noise_p95, self.pbs.noise_p99, self.pbs.noise_maximum
        );
        println!("minimum decoding margin: {}", self.decoding_margin);
        println!(
            "maximum noise / margin: {:.6}",
            self.pbs.noise_maximum as f64 / self.decoding_margin as f64
        );
        println!("failures: {}/{}", self.pbs.failures, config.trials);
        if self.pbs.failures == 0 {
            println!(
                "zero-failure 95% empirical upper bound: {:.3e}",
                (3.0 / config.trials as f64).min(1.0)
            );
        }
        println!("security estimate: not evaluated");
    }
}

impl SpectrumStats {
    fn print(&self, label: &str) {
        println!(
            "{label}: min|FFT(f)|^2={:.6e}, max|1/FFT(f)|={:.6e}, max inverse residual={:.6e}, min/epsilon={:.6e}",
            self.minimum_norm_squared,
            self.maximum_inverse_norm,
            self.maximum_inverse_residual,
            self.minimum_norm_squared / f64::EPSILON
        );
    }
}

fn percentile<T: Copy>(sorted: &[T], percentage: usize) -> T {
    let index = (sorted.len() - 1) * percentage / 100;
    sorted[index]
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{:.3} s", duration.as_secs_f64())
    } else if duration.as_millis() > 0 {
        format!("{:.3} ms", duration.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.3} us", duration.as_secs_f64() * 1_000_000.0)
    }
}
