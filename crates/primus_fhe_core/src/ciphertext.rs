/// Lwe Ciphertext
pub type LweCiphertext<T> = primus_lattice::lwe::Lwe<Vec<T>>;

/// CmLwe Ciphertext
pub type MultiMsgLweCiphertext<T> = primus_lattice::lwe::MultiMsgLwe<Vec<T>>;
