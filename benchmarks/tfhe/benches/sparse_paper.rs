//! Paper-shaped comparisons are deliberately separate from ordinary profiles.
#[path = "sparse_paper/mod.rs"]
mod paper;
fn main() {
    primus_tfhe_benchmarks::measurement::run("sparse_paper", paper::benchmark);
}
