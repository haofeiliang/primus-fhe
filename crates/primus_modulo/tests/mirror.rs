use primus_modulo::{DotProductModulo, DotProductModuloIter, OnceModuloSlice};
use primus_reduce::{ReduceDotProduct, ReduceOnceSlice};

struct NonCopyModulus(u32);

impl ReduceOnceSlice<u32> for NonCopyModulus {
    fn reduce_once_slice_assign(self, values: &mut [u32]) {
        for value in values {
            if *value >= self.0 {
                *value -= self.0;
            }
        }
    }

    fn reduce_once_slice_to(self, input: &[u32], output: &mut [u32]) {
        assert_eq!(input.len(), output.len());
        for (&value, output) in input.iter().zip(output) {
            *output = if value >= self.0 {
                value - self.0
            } else {
                value
            };
        }
    }
}

impl ReduceDotProduct<u32> for NonCopyModulus {
    fn reduce_dot_product(self, a: &[u32], b: &[u32]) -> u32 {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b)
            .fold(0, |acc, (&a, &b)| (acc + a * b) % self.0)
    }

    fn reduce_dot_product_iter(
        self,
        a: impl IntoIterator<Item = u32>,
        b: impl IntoIterator<Item = u32>,
    ) -> u32 {
        a.into_iter()
            .zip(b)
            .fold(0, |acc, (a, b)| (acc + a * b) % self.0)
    }
}

#[test]
fn value_side_slice_mirror_accepts_non_copy_modulus() {
    let mut values = [8, 13];
    values.once_modulo_slice_assign(NonCopyModulus(7));
    assert_eq!(values, [1, 6]);

    let a = [2, 3];
    let b = [4, 5];
    assert_eq!(a.dot_product_modulo(&b, NonCopyModulus(7)), 2);
    assert_eq!(
        a.into_iter().dot_product_modulo_iter(b, NonCopyModulus(7)),
        2
    );
}
