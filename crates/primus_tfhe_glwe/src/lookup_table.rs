use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{
    FactorizedLookupTable, FactorizedPbsCodecs, LookupTableCompiler, LookupTableError,
    PbsMessageConfig, RoundedPbsCodecs,
};

use crate::TfheParameters;

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M> {
    /// Prepares input and output codecs for ordinary PBS or ManyLUT.
    ///
    /// [`PbsMessageConfig::new`] defaults to equal plaintext moduli; use
    /// [`PbsMessageConfig::with_output_modulus`] to change the output domain.
    /// All ciphertext roles share this family's modulus. Codec errors are
    /// reported here; LUT geometry and noise requirements remain operation-specific.
    pub fn pbs_codecs(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<RoundedPbsCodecs<T, M>, LookupTableError> {
        messages.try_rounded_codecs(self.cipher_modulus(), self.cipher_modulus())
    }

    /// Prepares Rounded input and Scaled output codecs for factorized MVB.
    ///
    /// Uses the same default/override rules as [`Self::pbs_codecs`]. Inherits
    /// [`PbsMessageConfig::try_factorized_codecs`]'s scale and error contracts;
    /// factorization-specific conditions are checked when compiling the program.
    pub fn factorized_pbs_codecs(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<FactorizedPbsCodecs<T, M>, LookupTableError> {
        messages.try_factorized_codecs(self.cipher_modulus(), self.cipher_modulus())
    }

    /// Binds prepared Rounded codecs for ordinary, interleaved or odd-domain PBS.
    ///
    /// Checks the input at external q and LUT output at accumulator Q. The
    /// compiler copies the selected encoding state without preparing a default
    /// output first; input and output plaintext moduli remain independent.
    /// Bind `codecs.output_codec()` to the output decryptor at external q.
    /// Program geometry and output ranges are checked by the compiler methods.
    pub fn lookup_table_compiler<OM: RingContext<T>>(
        &self,
        codecs: &RoundedPbsCodecs<T, OM, M>,
    ) -> Result<LookupTableCompiler<T, M, M, OM>, LookupTableError> {
        if codecs.input_codec().ciphertext_modulus().explicit_value()
            != self.cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::InputModulusMismatch);
        }
        LookupTableCompiler::try_new(
            self.blind_rotation_ggsw().poly_length(),
            codecs.input_codec(),
            self.cipher_modulus(),
            codecs.lut_output_codec(),
        )
    }

    /// Compiles a coefficient-domain MVB program from prepared Rounded/Scaled codecs.
    ///
    /// `input_domain_len` selects a nonempty prefix of `0..ceil(t_in/2)`;
    /// `output_count` is positive and unpadded. The callback must return values
    /// in `0..t_out`. Input q and LUT-output Q must match these parameters.
    /// The returned program owns its coefficients, without borrowing codecs or
    /// parameters. Backend context methods also prepare its NTT/Fourier factors.
    /// Callback order, scale conditions and noise requirements follow
    /// [`FactorizedLookupTable::try_new`]. Returned LWE messages use
    /// `codecs.output_codec()` at the same ciphertext modulus.
    pub fn compile_factorized_lookup_table_fn<OM: RingContext<T>, F>(
        &self,
        codecs: &FactorizedPbsCodecs<T, OM, M>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<FactorizedLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        if codecs.input_codec().ciphertext_modulus().explicit_value()
            != self.cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::InputModulusMismatch);
        }
        if codecs
            .lut_output_codec()
            .ciphertext_modulus()
            .explicit_value()
            != self.cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        FactorizedLookupTable::try_new(
            input_domain_len,
            self.blind_rotation_ggsw().poly_length(),
            output_count,
            codecs.input_codec(),
            codecs.lut_output_codec(),
            function,
        )
    }
}
