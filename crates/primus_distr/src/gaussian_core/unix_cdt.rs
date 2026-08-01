use rug::{Float, az::Cast};

use super::GaussianParameters;

const PRECISION: u32 = 512;

/// Builds the 256-bit CDT shared by signed and modular output adapters.
#[inline(always)]
pub(crate) fn build_unix_cdt(parameters: GaussianParameters) -> (f64, Vec<[u64; 4]>) {
    let standard_deviation = parameters.standard_deviation();
    let length = parameters.maximum_magnitude() as usize + 1;
    let standard_deviation = Float::with_val(PRECISION, standard_deviation);
    let negative_twice_variance_reciprocal = -(standard_deviation.square() * 2u32).recip();

    let mut pdf = vec![Float::new(PRECISION); length];
    pdf[0] = Float::with_val(PRECISION, 1) / 2;
    let mut previous = negative_twice_variance_reciprocal.clone().exp();
    pdf[1] = previous.clone();
    for (magnitude, probability) in pdf.iter_mut().enumerate().skip(2) {
        let factor =
            Float::with_val(PRECISION, 2 * magnitude - 1) * &negative_twice_variance_reciprocal;
        previous *= factor.exp();
        *probability = previous.clone();
    }

    let sum = pdf
        .iter()
        .fold(Float::new(PRECISION), |sum, value| sum + value);
    let mut cumulative_probability = Float::new(PRECISION);
    let mut cdt = Vec::with_capacity(length + 1);
    cdt.push(Float::new(PRECISION));
    for probability in &pdf {
        cumulative_probability += probability;
        if cumulative_probability < sum {
            cdt.push(Float::with_val(PRECISION, &cumulative_probability / &sum));
        } else {
            cdt.push(Float::with_val(PRECISION, 1));
            break;
        }
    }
    assert_eq!(cdt.len(), length + 1);

    let scalar = rug::Integer::from(1) << 256;
    let cdt = cdt
        .into_iter()
        .map(|probability| {
            if probability == 1 {
                return [u64::MAX; 4];
            }

            let scaled: Float = probability * &scalar;
            let integer: rug::Integer = scaled.cast();
            let digits = integer.to_digits::<u64>(rug::integer::Order::Lsf);
            debug_assert!(digits.len() <= 4, "CDT value exceeds 256 bits");

            let mut result = [0; 4];
            let length = digits.len().min(4);
            result[..length].copy_from_slice(&digits[..length]);
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
