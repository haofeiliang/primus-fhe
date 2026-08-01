use std::convert::Infallible;

use primus_distr::{BinaryDistr, DiscreteGaussian, SignedDiscreteGaussian, SparseTernaryDistr};
use rand::{SeedableRng, TryRng, distr::Distribution, rngs::StdRng};

struct CountingRng(u32);

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let value = self.0;
        self.0 = self.0.wrapping_add(1);
        Ok(value)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let low = u64::from(self.try_next_u32()?);
        let high = u64::from(self.try_next_u32()?);
        Ok(low | (high << 32))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in destination.chunks_mut(4) {
            let bytes = self.try_next_u32()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

#[test]
fn scalar_bit_samplers_map_every_low_bit_pattern() {
    let mut binary_rng = CountingRng(0);
    let binary: Vec<u8> = (0..4)
        .map(|_| BinaryDistr.sample(&mut binary_rng))
        .collect();
    assert_eq!(binary, [0, 1, 0, 1]);

    let ternary = SparseTernaryDistr::new(-1_i8);
    let mut ternary_rng = CountingRng(0);
    let ternary: Vec<i8> = (0..4).map(|_| ternary.sample(&mut ternary_rng)).collect();
    assert_eq!(ternary, [0, 0, 1, -1]);
}

#[test]
fn gaussian_facades_preserve_encoding_and_basic_moments() {
    const SAMPLE_COUNT: usize = 8_192;
    const SEED: u64 = 0x4449_5354_522d_3037;

    for (standard_deviation, expect_cdt) in [(3.19, true), (30.0, false)] {
        let modular = DiscreteGaussian::<u64>::new(standard_deviation, u64::MAX).unwrap();
        let signed = SignedDiscreteGaussian::<i64>::new(standard_deviation).unwrap();

        assert_eq!(matches!(&modular, DiscreteGaussian::Cdt(_)), expect_cdt);
        assert_eq!(
            matches!(&signed, SignedDiscreteGaussian::Cdt(_)),
            expect_cdt
        );

        let mut modular_rng = StdRng::seed_from_u64(SEED);
        let mut signed_rng = StdRng::seed_from_u64(SEED);
        let mut sum = 0.0;
        let mut squared_sum = 0.0;

        for _ in 0..SAMPLE_COUNT {
            let modular_sample = modular.sample(&mut modular_rng) as i64;
            let signed_sample = signed.sample(&mut signed_rng);
            assert_eq!(modular_sample, signed_sample);

            let sample = signed_sample as f64;
            sum += sample;
            squared_sum += sample * sample;
        }

        let mean = sum / SAMPLE_COUNT as f64;
        let variance = squared_sum / SAMPLE_COUNT as f64 - mean * mean;
        let measured_standard_deviation = variance.sqrt();

        assert!(mean.abs() < standard_deviation * 0.12);
        assert!(
            (measured_standard_deviation / standard_deviation - 1.0).abs() < 0.12,
            "requested σ={standard_deviation}, measured σ={measured_standard_deviation}"
        );
    }
}
