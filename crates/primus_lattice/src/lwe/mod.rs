mod extract;
mod multiple_message;
mod single_message;

pub use multiple_message::MultiMsgLwe;
pub use single_message::Lwe;

/// TFHE torus LWE ciphertext (coefficient domain).
///
/// Layout: `[a_1, ..., a_k, b]` — `k` mask elements + 1 body element.
pub type TorusLwe<S> = Lwe<S>;
