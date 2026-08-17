mod ntru_params;

use clap::{Parser, Subcommand};

/// Primus FHE developer tasks.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Developer task to execute.
    #[command(subcommand)]
    command: Command,
}

/// Available developer tasks.
#[derive(Subcommand)]
enum Command {
    /// Validates one experimental NTRU TFHE parameter set.
    NtruParams(ntru_params::Config),
}

fn main() {
    let result = match Cli::parse().command {
        Command::NtruParams(config) => ntru_params::run(config),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
