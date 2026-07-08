/// Lwe Ciphertext
pub type LweCiphertext<T> = primus_lattice::lwe::Lwe<Vec<T>>;

/// CmLwe Ciphertext
pub type MultiMsgLweCiphertext<T> = primus_lattice::lwe::MultiMsgLwe<Vec<T>>;

/// Rlwe Ciphertext
pub type RlweCiphertext<T> = primus_lattice::rlwe::Rlwe<T>;

/// Ntt version Rlwe Ciphertext
pub type NttRlweCiphertext<T> = primus_lattice::rlwe::NttRlwe<T>;

/// Glwe Ciphertext
pub type GlweCiphertext<T> = primus_lattice::glwe::Glwe<T>;

/// Ntt version Glwe Ciphertext
pub type NttGlweCiphertext<T> = primus_lattice::glwe::NttGlwe<T>;

/// Glwe Ciphertext
pub type CrtGlweCiphertext<T> = primus_lattice::glwe::CrtGlwe<T>;

/// Ntt version Glwe Ciphertext
pub type DcrtGlweCiphertext<T> = primus_lattice::glwe::DcrtGlwe<T>;

/// Ntru Ciphertext
pub type NtruCiphertext<T> = primus_lattice::ntru::Ntru<T>;

/// Ntt version Ntru Ciphertext
pub type NttNtruCiphertext<T> = primus_lattice::ntru::NttNtru<T>;
