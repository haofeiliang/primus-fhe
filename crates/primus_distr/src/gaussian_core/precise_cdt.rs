use dashu_float::{Context, FBig, Repr, round::mode::HalfEven};
use dashu_int::IBig;

use super::GaussianParameters;

const PRECISION: usize = 512;

type BigFloat = FBig<HalfEven, 2>;

#[inline]
fn float_from_integer(context: Context<HalfEven>, value: impl Into<IBig>) -> BigFloat {
    context.convert_int::<2>(value.into()).value()
}

#[inline]
fn float_zero(context: Context<HalfEven>) -> BigFloat {
    FBig::from_repr(Repr::zero(), context)
}

#[inline]
fn float_one(context: Context<HalfEven>) -> BigFloat {
    FBig::from_repr(Repr::one(), context)
}

/// Builds the 256-bit CDT shared by signed and modular output adapters.
#[inline]
pub(crate) fn build_precise_cdt(parameters: GaussianParameters) -> (f64, Vec<[u64; 4]>) {
    let standard_deviation = parameters.standard_deviation();
    let length = parameters.maximum_magnitude() as usize + 1;
    let context = Context::<HalfEven>::new(PRECISION);
    let standard_deviation = BigFloat::try_from(standard_deviation)
        .expect("validated standard deviation must be finite")
        .with_precision(PRECISION)
        .value();
    let negative_twice_variance_reciprocal = -(standard_deviation.sqr() * 2u32).inv();

    let mut pdf = vec![float_zero(context); length];
    pdf[0] = float_one(context) / 2u32;
    let mut previous = negative_twice_variance_reciprocal.exp();
    pdf[1] = previous.clone();

    // If c = -1/(2σ²), then p_m / p_{m-1} = exp((2m - 1)c).
    // Consecutive ratios differ by the constant exp(2c), so two 512-bit
    // exponentials are enough and all subsequent work retains 512-bit guard
    // precision until the final 256-bit threshold conversion.
    let ratio_step = (&negative_twice_variance_reciprocal * 2u32).exp();
    let mut ratio = &previous * &ratio_step;
    for probability in pdf.iter_mut().skip(2) {
        previous *= &ratio;
        *probability = previous.clone();
        ratio *= &ratio_step;
    }

    let sum = pdf
        .iter()
        .fold(float_zero(context), |sum, value| sum + value);
    let scalar_integer = IBig::ONE << 256usize;
    let scalar = float_from_integer(context, scalar_integer.clone());
    let mut cumulative_probability = float_zero(context);
    let mut cdt = vec![[0; 4]; length + 1];
    for (probability, bound) in pdf.iter().zip(&mut cdt[1..]) {
        cumulative_probability += probability;
        *bound = if cumulative_probability < sum {
            let scaled = (&cumulative_probability / &sum) * &scalar;
            let integer = scaled.to_int().value();
            assert!(
                integer <= scalar_integer,
                "rounded CDT probability must not exceed 2^256"
            );
            if integer == scalar_integer {
                // Half-even conversion can round a value just below 2^256 up
                // to the unrepresentable upper endpoint.
                [u64::MAX; 4]
            } else {
                let words = integer
                    .as_ubig()
                    .expect("scaled CDT probability must be non-negative")
                    .as_words();

                let mut result = [0; 4];
                result[..words.len()].copy_from_slice(words);
                result
            }
        } else {
            [u64::MAX; 4]
        };
    }

    (parameters.standard_deviation(), cdt)
}

#[inline(always)]
pub(crate) fn compare_u256(left: &[u64; 4], right: &[u64; 4]) -> std::cmp::Ordering {
    for index in (0..4).rev() {
        match left[index].cmp(&right[index]) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}
