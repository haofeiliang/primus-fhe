use rand::distr::Distribution;
use rand::rngs::StdRng;

pub const RNG_SEED: u64 = 0x696e_7465_6765_725f;

pub fn sampled_values<T, D>(rng: &mut StdRng, distribution: &D, len: usize) -> Vec<T>
where
    D: Distribution<T>,
{
    (0..len).map(|_| distribution.sample(rng)).collect()
}
