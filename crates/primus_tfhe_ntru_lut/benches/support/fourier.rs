// Fourier evaluation uses the public API and shared representative parameters.
use std::hint::black_box;

use super::{CONFIG, INPUT, benchmark_lut_creation, digit, heap};
use criterion::{Criterion, SamplingMode, Throughput};
use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_ntru::SecretKeyDistr;
use primus_test_allocations::measure;
use primus_tfhe_ntru_fourier::TfheContext;
use primus_tfhe_ntru_lut::{FourierLookupTableEvaluator, HighPrecisionLookupTable};
use primus_tfhe_test_support::parameters::ntru;
use rand::{SeedableRng, rngs::StdRng};

pub fn benchmark<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str) {
    let parameters = ntru::circuit(NativeModulus::<T>::new(), 8, SecretKeyDistr::UniformBinary);
    let name = format!("lookup/{backend}/u{}/n800_N1024/c8_d5_o8", T::BITS);
    if backend == "rustfft" {
        benchmark_lut_creation(c, &name, &parameters);
    }
    let mut fixture = None;
    let mut reported = false;
    let mut group = c.benchmark_group(&name);
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Elements(CONFIG.output_chunk_count as u64));
    group.bench_function("evaluate", |b| {
        let (context, client, server, table, input) = fixture.get_or_insert_with(|| {
            let context =
                TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(parameters.clone())
                    .unwrap();
            let mut rng = StdRng::seed_from_u64(42);
            let ((client, server), keys) = measure(|| {
                context
                    .try_generate_keys(Some(ntru::cbs::<T>()), &mut rng)
                    .unwrap()
            });
            heap(&format!("{name}/client_and_server_keys"), keys);
            let (table, storage) = measure(|| {
                HighPrecisionLookupTable::try_new(context.parameters(), CONFIG, digit::<T>).unwrap()
            });
            heap(&format!("{name}/public_lut"), storage);
            let encryptor = context.encryptor(&client).unwrap();
            let input: Vec<_> = (0..CONFIG.input_chunk_count)
                .map(|i| {
                    encryptor
                        .encrypt_padded(T::as_from((INPUT >> (2 * i)) & 3), &mut rng)
                        .unwrap()
                })
                .collect();
            (context, client, server, table, input)
        });
        let (mut evaluator, workspace) =
            measure(|| FourierLookupTableEvaluator::try_new(context, server, table).unwrap());
        let (mut output, output_memory) = measure(|| evaluator.allocate_output());
        if !reported {
            heap(&format!("{name}/workspace"), workspace);
            heap(&format!("{name}/outputs"), output_memory);
            // Instrument only this untimed call. Keep decryption outside the
            // allocation probe so its client workspace is not charged to lookup.
            let (_, online) = measure(|| evaluator.evaluate_to(input, &mut output));
            assert_eq!(online.count, 0);
            eprintln!("online_allocations,{name},{}", online.count);
            let decryptor = context.decryptor(client).unwrap();
            for (i, chunk) in output.iter().enumerate() {
                assert_eq!(decryptor.decrypt(chunk).unwrap(), digit::<T>(INPUT, i));
            }
            reported = true;
        }
        b.iter(|| evaluator.evaluate_to(black_box(input), black_box(&mut output)));
    });
    group.finish();
}
