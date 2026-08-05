/// Lwe Ciphertext
pub type LweCiphertext<T> = primus_lattice::lwe::Lwe<Vec<T>>;

/// CmLwe Ciphertext
pub type MultiMsgLweCiphertext<T> = primus_lattice::lwe::MultiMsgLwe<Vec<T>>;

/// Ntt version Rlwe Ciphertext
pub type NttRlweCiphertext<T> = primus_lattice::rlwe::NttRlwe<T>;

/// Glwe Ciphertext
pub type GlweCiphertext<T> = primus_lattice::glwe::Glwe<T>;

/// Ntt version Glwe Ciphertext
pub type NttGlweCiphertext<T> = primus_lattice::glwe::NttGlwe<T>;

/// Fourier-domain Glwe Ciphertext
pub type FourierGlweCiphertext<S> = primus_lattice::glwe::FourierGlwe<S>;

/// NTT-domain GLev ciphertext.
pub type NttGlevCiphertext<S> = primus_lattice::glev::NttGlev<S>;

/// Fourier-domain GLev ciphertext.
pub type FourierGlevCiphertext<S> = primus_lattice::glev::FourierGlev<S>;

/// NTT-domain GGSW ciphertext.
pub type NttGgswCiphertext<S> = primus_lattice::ggsw::NttGgsw<S>;

/// Fourier-domain GGSW ciphertext.
pub type FourierGgswCiphertext<S> = primus_lattice::ggsw::FourierGgsw<S>;

/// Glwe Ciphertext
pub type CrtGlweCiphertext<T> = primus_lattice::glwe::CrtGlwe<T>;

/// Ntt version Glwe Ciphertext
pub type DcrtGlweCiphertext<T> = primus_lattice::glwe::DcrtGlwe<T>;
