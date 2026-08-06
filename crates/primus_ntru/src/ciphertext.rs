/// Coefficient-domain scalar NTRU ciphertext.
pub type NtruCiphertext<S> = primus_lattice::ntru::Ntru<S>;

/// NTT-domain scalar NTRU ciphertext.
pub type NttNtruCiphertext<S> = primus_lattice::ntru::NttNtru<S>;

/// Fourier-domain scalar NTRU ciphertext.
pub type FourierNtruCiphertext<S> = primus_lattice::ntru::FourierNtru<S>;

/// Coefficient-domain NLev ciphertext.
pub type NlevCiphertext<S> = primus_lattice::nlev::Nlev<S>;

/// NTT-domain NLev ciphertext.
pub type NttNlevCiphertext<S> = primus_lattice::nlev::NttNlev<S>;

/// Fourier-domain NLev ciphertext.
pub type FourierNlevCiphertext<S> = primus_lattice::nlev::FourierNlev<S>;

/// Coefficient-domain NGSW ciphertext.
pub type NgswCiphertext<S> = primus_lattice::ngsw::Ngsw<S>;

/// NTT-domain NGSW ciphertext.
pub type NttNgswCiphertext<S> = primus_lattice::ngsw::NttNgsw<S>;

/// Fourier-domain NGSW ciphertext.
pub type FourierNgswCiphertext<S> = primus_lattice::ngsw::FourierNgsw<S>;
