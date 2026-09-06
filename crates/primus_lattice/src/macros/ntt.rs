//! NTT and CRT ↔ DCRT domain transforms.
//!
//! Generates `into_ntt_form` / `write_ntt_form` and `into_coeff_form` /
//! `write_coeff_form` for both single-modulus (NTT) and multi-modulus
//! (CRT ↔ DCRT) representations.

macro_rules! impl_ntt {
    ($cipher:ident,$ntt_cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form.
            #[inline]
            pub fn into_ntt_form<Table>(mut self, ntt_table: &Table) -> $ntt_cipher<S>
            where
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                self.0.chunks_exact_mut(poly_length).for_each(|poly| {
                    ntt_table.transform_slice(poly);
                });
                $ntt_cipher::new(self.0)
            }
        }

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form and stores in `output`.
            #[inline]
            pub fn write_ntt_form<Table, A>(&self, output: &mut $ntt_cipher<A>, ntt_table: &Table)
            where
                A: DataMut<Elem = T>,
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                output.0.copy_from_slice(self.as_ref());
                output.0.chunks_exact_mut(poly_length).for_each(|poly| {
                    ntt_table.transform_slice(poly);
                });
            }
        }
    };
}

macro_rules! impl_intt {
    ($ntt_cipher:ident,$cipher:ident) => {
        impl<S, T> $ntt_cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form.
            #[inline]
            pub fn into_coeff_form<Table>(mut self, ntt_table: &Table) -> $cipher<S>
            where
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                self.0.chunks_exact_mut(poly_length).for_each(|poly| {
                    ntt_table.inverse_transform_slice(poly);
                });
                $cipher::new(self.0)
            }
        }

        impl<S, T> $ntt_cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form and stores in `output`.
            #[inline]
            pub fn write_coeff_form<Table, A>(&self, output: &mut $cipher<A>, ntt_table: &Table)
            where
                A: DataMut<Elem = T>,
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                output.0.copy_from_slice(self.as_ref());
                output.0.chunks_exact_mut(poly_length).for_each(|values| {
                    ntt_table.inverse_transform_slice(values);
                });
            }
        }
    };
}

#[cfg(feature = "rns")]
macro_rules! impl_crt_ntt {
    ($cipher:ident,$ntt_cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form.
            #[inline]
            pub fn into_ntt_form<Table>(
                self,
                table: &primus_ntt::DcrtTable<Table>,
            ) -> $ntt_cipher<S>
            where
                Table: primus_ntt::NttTable<ValueT = T>,
            {
                let crt_poly_length = table.crt_poly_length();
                let Self(mut data) = self;
                data.chunks_exact_mut(crt_poly_length).for_each(|crt_poly| {
                    table.transform_slice(crt_poly);
                });
                $ntt_cipher::new(data)
            }
        }

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form and stores in `output`.
            #[inline]
            pub fn write_ntt_form<Table, A>(
                &self,
                output: &mut $ntt_cipher<A>,
                table: &primus_ntt::DcrtTable<Table>,
            ) where
                Table: primus_ntt::NttTable<ValueT = T>,
                A: DataMut<Elem = T>,
            {
                let crt_poly_length = table.crt_poly_length();
                output.0.copy_from_slice(self.as_ref());
                output
                    .0
                    .chunks_exact_mut(crt_poly_length)
                    .for_each(|crt_poly| {
                        table.transform_slice(crt_poly);
                    });
            }
        }
    };
}

#[cfg(feature = "rns")]
macro_rules! impl_crt_intt {
    ($ntt_cipher:ident,$cipher:ident) => {
        impl<S, T> $ntt_cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form.
            #[inline]
            pub fn into_coeff_form<Table>(self, table: &primus_ntt::DcrtTable<Table>) -> $cipher<S>
            where
                Table: primus_ntt::NttTable<ValueT = T>,
            {
                let crt_poly_length = table.crt_poly_length();
                let Self(mut data) = self;
                data.chunks_exact_mut(crt_poly_length).for_each(|crt_poly| {
                    table.inverse_transform_slice(crt_poly);
                });
                $cipher::new(data)
            }
        }

        impl<S, T> $ntt_cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form and stores in `output`.
            #[inline]
            pub fn write_coeff_form<Table, A>(
                &self,
                output: &mut $cipher<A>,
                table: &primus_ntt::DcrtTable<Table>,
            ) where
                Table: primus_ntt::NttTable<ValueT = T>,
                A: DataMut<Elem = T>,
            {
                let crt_poly_length = table.crt_poly_length();
                output.0.copy_from_slice(self.as_ref());
                output
                    .0
                    .chunks_exact_mut(crt_poly_length)
                    .for_each(|crt_poly| {
                        table.inverse_transform_slice(crt_poly);
                    });
            }
        }
    };
}
