use cudarc::driver::CudaContext;
use primus_cuda::cuda_smoke;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = CudaContext::new(0)?;
    let stream = context.new_stream()?;
    let result = cuda_smoke(&stream, &[0, 1, u32::MAX])?;
    assert_eq!(result, [1, 2, 0]);
    println!("{}: CUDA kernel returned {result:?}", context.name()?);
    Ok(())
}
