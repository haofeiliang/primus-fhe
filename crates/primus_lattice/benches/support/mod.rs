// Vary one dimension at a time: baseline, polynomial length, gadget levels.
// These are arithmetic workloads, not recommended cryptographic parameters.
pub const PRODUCT_CASES: &[(u32, usize)] = &[(10, 3), (11, 3), (10, 2)];
pub const LOG_B: u32 = 8;
