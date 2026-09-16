//! Errors from LUT compilation and evaluator construction.

/// An error produced while constructing a TFHE evaluator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheEvaluationError {
    /// The server key was generated for a different parameter layout.
    #[error("TFHE server key is incompatible with the evaluation context")]
    IncompatibleServerKey,
}

/// An error produced while compiling a TFHE lookup table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupTableError {
    /// The polynomial length is not a non-zero power of two, or `2N` cannot
    /// be represented for modulus switching.
    #[error("invalid lookup-table polynomial length")]
    InvalidPolynomialLength,
    /// The rounded input encoding requires `t > 1` and explicit `q > t`.
    #[error("invalid lookup-table input encoding")]
    InvalidInputEncoding,
    /// The selected input domain must be a non-empty prefix of the front half.
    #[error("lookup-table input domain {domain_len} must belong to 1..={max_domain_len}")]
    InvalidInputDomain {
        /// Supplied domain length.
        domain_len: usize,
        /// Largest independently programmable domain length.
        max_domain_len: usize,
    },
    /// A raw output is not canonical under the accumulator modulus.
    #[error("encoded lookup-table output for input {input} is outside the accumulator modulus")]
    EncodedOutputOutOfRange {
        /// Input whose encoded output is invalid.
        input: usize,
    },
    /// The plaintext modulus cannot be used as a platform-sized domain length.
    #[error("plaintext modulus is too large for lookup-table compilation")]
    PlaintextModulusTooLarge,
    /// More plaintext values exist than available rotation coefficients.
    #[error(
        "plaintext domain of length {domain_len} exceeds rotation domain of length {rotation_domain_len}"
    )]
    PlaintextDomainTooLarge {
        /// Number of independently programmable plaintext inputs.
        domain_len: usize,
        /// Number of accumulator coefficients.
        rotation_domain_len: usize,
    },
    /// Adjacent messages, or the last message and the negacyclic boundary,
    /// collide after encoding and modulus switching.
    #[error(
        "rotation-center collision between inputs {first_input} and {second_input} at exponent {exponent}"
    )]
    RotationCenterCollision {
        /// First adjacent plaintext input.
        first_input: usize,
        /// Second adjacent input, or the domain length at the negacyclic boundary.
        second_input: usize,
        /// Colliding rotation exponent.
        exponent: usize,
    },
    /// A slice has the wrong front-half domain length.
    #[error("lookup-table domain length mismatch: expected {expected}, got {actual}")]
    DomainLengthMismatch {
        /// Required output count.
        expected: usize,
        /// Supplied output count.
        actual: usize,
    },
    /// The flattened PBSManyLUT table length does not fit in `usize`.
    #[error("many-LUT flattened table length overflows usize")]
    ManyTableLengthOverflow,
    /// A lookup table must have at least one output.
    #[error("lookup table requires at least one output")]
    EmptyOutputs,
    /// The requested number of outputs exceeds the accumulator length.
    #[error("many-LUT output count {output_count} exceeds polynomial length {poly_length}")]
    OutputCountTooLarge {
        /// Supplied output count.
        output_count: usize,
        /// Accumulator polynomial length.
        poly_length: usize,
    },
    /// A function output lies outside the plaintext domain.
    #[error("lookup-table output for input {input} is outside the plaintext domain")]
    OutputOutOfRange {
        /// Input whose output is invalid.
        input: usize,
    },
}
