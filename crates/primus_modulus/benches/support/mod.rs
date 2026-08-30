use core::time::Duration;

use criterion::Criterion;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform, uniform::SampleUniform},
    rngs::StdRng,
};

const RNG_SEED: u64 = 0x6d6f_6475_6c75_735f;

pub fn benchmark_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

pub fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(RNG_SEED ^ seed)
}

pub struct Inputs<T> {
    pub lhs: Vec<T>,
    pub rhs: Vec<T>,
}

pub fn inputs<T>(modulus: T, len: usize) -> Inputs<T>
where
    T: Copy + Default + Into<u64> + SampleUniform,
{
    let mut rng = seeded_rng(modulus.into() ^ len as u64);
    Inputs {
        lhs: values(&mut rng, len, T::default(), modulus),
        rhs: values(&mut rng, len, T::default(), modulus),
    }
}

pub fn values<T>(rng: &mut StdRng, len: usize, low: T, high: T) -> Vec<T>
where
    T: Copy + SampleUniform,
{
    let distribution = Uniform::new(low, high).unwrap();
    distribution.sample_iter(rng).take(len).collect()
}
