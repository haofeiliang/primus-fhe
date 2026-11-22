use std::{env, path::PathBuf, process::Command};

fn main() {
    const SOURCE: &str = "kernels/ntt.cu";
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-changed=kernels/external_product.cuh");
    println!("cargo:rerun-if-changed=kernels/block_rotation.cuh");
    println!("cargo:rerun-if-env-changed=PRIMUS_CUDA_NVCC");
    println!("cargo:rerun-if-env-changed=PRIMUS_CUDA_ARCH");
    if env::var_os("CARGO_FEATURE_CUDA").is_none() {
        return;
    }

    let nvcc = env::var_os("PRIMUS_CUDA_NVCC").unwrap_or_else(|| "nvcc".into());
    let arch = env::var("PRIMUS_CUDA_ARCH").unwrap_or_else(|_| "compute_80".into());
    let ptx =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR")).join("primus_cuda.ptx");
    let status = Command::new(&nvcc)
        .args(["--ptx", "--std=c++17", "--generate-line-info"])
        .args(["--gpu-architecture", &arch, SOURCE, "--output-file"])
        .arg(ptx)
        .status()
        .unwrap_or_else(|error| {
            panic!("cannot run {nvcc:?}: {error}; set PRIMUS_CUDA_NVCC to the path to nvcc")
        });
    assert!(
        status.success(),
        "{nvcc:?} failed to compile {SOURCE} for {arch}: {status}"
    );
}
