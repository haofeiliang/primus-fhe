use primus_integer::FheUint;
use primus_lattice::context::DcrtGlevContext;
use primus_poly::CrtPolynomial;

pub struct CrtGlweAutoContext<T: FheUint> {
    auto_crt_poly: CrtPolynomial<Vec<T>>,
    glev_context: DcrtGlevContext<T>,
}

impl<T: FheUint> CrtGlweAutoContext<T> {
    pub fn new(
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        let auto_crt_poly = CrtPolynomial::zero(crt_poly_len);
        let glev_context =
            DcrtGlevContext::new(poly_length, crt_poly_len, big_uint_poly_len, moduli_count);
        Self {
            auto_crt_poly,
            glev_context,
        }
    }

    pub fn as_mut(&mut self) -> (&mut CrtPolynomial<Vec<T>>, &mut DcrtGlevContext<T>) {
        (&mut self.auto_crt_poly, &mut self.glev_context)
    }

    pub fn compose_buffer_mut(&mut self) -> &mut [T] {
        self.glev_context.compose_buffer_mut()
    }
}

mod crt;
mod dcrt;

pub use crt::{CoeffAutoHelper, CrtGlweAutoKey, crt_poly_auto_inplace};
pub use dcrt::{DcrtGlweAutoKey, NttAutoHelper, dcrt_poly_ntt_auto_inplace};
