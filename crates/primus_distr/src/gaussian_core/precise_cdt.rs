use dashu_float::{Context, FBig, round::mode::HalfEven};
use dashu_int::IBig;

use super::GaussianParameters;

const PRECISION: usize = 512;

type BigFloat = FBig<HalfEven, 2>;

#[inline]
fn float_from_integer(context: Context<HalfEven>, value: impl Into<IBig>) -> BigFloat {
    context.convert_int::<2>(value.into()).value()
}

/// Builds the 256-bit CDT shared by signed and modular output adapters.
#[inline(always)]
pub(crate) fn build_precise_cdt(parameters: GaussianParameters) -> (f64, Vec<[u64; 4]>) {
    let standard_deviation = parameters.standard_deviation();
    let length = parameters.maximum_magnitude() as usize + 1;
    let context = Context::<HalfEven>::new(PRECISION);
    let standard_deviation = BigFloat::try_from(standard_deviation)
        .expect("validated standard deviation must be finite")
        .with_precision(PRECISION)
        .value();
    let negative_twice_variance_reciprocal = -(standard_deviation.sqr() * 2u32).inv();

    let mut pdf = vec![float_from_integer(context, 0); length];
    pdf[0] = float_from_integer(context, 1) / 2u32;
    let mut previous = negative_twice_variance_reciprocal.exp();
    pdf[1] = previous.clone();
    for (magnitude, probability) in pdf.iter_mut().enumerate().skip(2) {
        let factor =
            float_from_integer(context, 2 * magnitude - 1) * &negative_twice_variance_reciprocal;
        previous *= factor.exp();
        *probability = previous.clone();
    }

    let sum = pdf
        .iter()
        .fold(float_from_integer(context, 0), |sum, value| sum + value);
    let mut cumulative_probability = float_from_integer(context, 0);
    let mut cdt = Vec::with_capacity(length + 1);
    cdt.push(float_from_integer(context, 0));
    for probability in &pdf {
        cumulative_probability += probability;
        if cumulative_probability < sum {
            cdt.push(&cumulative_probability / &sum);
        } else {
            cdt.push(float_from_integer(context, 1));
            break;
        }
    }
    assert_eq!(cdt.len(), length + 1);

    let scalar = float_from_integer(context, IBig::ONE << 256usize);
    let cdt = cdt
        .into_iter()
        .map(|probability| {
            if probability == BigFloat::ONE {
                return [u64::MAX; 4];
            }

            let scaled = probability * &scalar;
            let integer = scaled.to_int().value();
            let words = integer
                .as_ubig()
                .expect("scaled CDT probability must be non-negative")
                .as_words();
            debug_assert!(words.len() <= 4, "CDT value exceeds 256 bits");

            let mut result = [0; 4];
            let length = words.len().min(4);
            result[..length].copy_from_slice(&words[..length]);
            result
        })
        .collect();

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
