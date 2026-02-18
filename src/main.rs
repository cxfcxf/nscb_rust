#![allow(dead_code)]

use clap::Parser;

mod cli;
mod crypto;
mod error;
mod formats;
mod keys;
mod ops;
mod util;

fn main() {
    env_logger::init();

    let args = cli::Args::parse();

    if let Err(e) = cli::dispatch(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
