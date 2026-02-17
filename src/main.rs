#![allow(dead_code)]

use clap::Parser;

mod error;
mod crypto;
mod keys;
mod formats;
mod ops;
mod util;
mod cli;

fn main() {
    env_logger::init();

    let args = cli::Args::parse();

    if let Err(e) = cli::dispatch(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
