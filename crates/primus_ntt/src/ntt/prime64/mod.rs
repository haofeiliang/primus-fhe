#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "x86_64")]
mod avx512;
mod precompute;
mod scalar;
mod table;

pub use table::U64NttTable;
