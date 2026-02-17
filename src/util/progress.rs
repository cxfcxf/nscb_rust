use std::env;

use console::Term;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

fn forced_draw_target() -> ProgressDrawTarget {
    // Use a TermLike target so indicatif does not auto-hide on non-TTY stderr.
    ProgressDrawTarget::term_like_with_hz(Box::new(Term::buffered_stderr()), 20)
}

fn env_truthy(name: &str) -> bool {
    match env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn progress_draw_target() -> ProgressDrawTarget {
    // Override behavior explicitly when requested.
    if env_truthy("NSCB_FORCE_PROGRESS") {
        return forced_draw_target();
    }

    // Default: force progress on Windows (common GUI/non-TTY launches),
    // keep terminal-aware behavior on Unix-like systems.
    if cfg!(windows) {
        forced_draw_target()
    } else {
        ProgressDrawTarget::stderr_with_hz(20)
    }
}

/// Create a progress bar for file copy operations.
pub fn file_progress(size: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(size);
    pb.set_draw_target(progress_draw_target());
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create a spinner for indeterminate operations.
pub fn spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_draw_target(progress_draw_target());
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

/// Create a progress bar for counting items.
pub fn item_progress(count: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(count);
    pb.set_draw_target(progress_draw_target());
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message(message.to_string());
    pb
}
