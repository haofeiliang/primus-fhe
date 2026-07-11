//! DCRT-domain RLWE operations — delegates to `glwe::dcrt`.
//!
//! RLWE is the dimension-1 special case of GLWE. All automorphism,
//! trace, and expand-coefficient operations pass through to the
//! GLWE implementations with `glwe_dimension = 1`.
