//! Optional Tailwind 4 build step.
//!
//! Default: the hand-written `assets/app.css` is shipped as-is.
//!
//! Opt-in: set `RELAY_TAILWIND=1` and install Tailwind 4. The build tries
//! these invocations in order, using whichever succeeds:
//!
//!   1. `npx @tailwindcss/cli -i assets/tw.css -o assets/app.css --minify`
//!      (the upstream-recommended flow for Tailwind 4)
//!   2. `tailwindcss -i assets/tw.css -o assets/app.css --minify`
//!      (the standalone single-binary CLI)
//!
//! So either `npm i -D tailwindcss @tailwindcss/cli` or a `brew install
//! tailwindcss` / binary download works.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let input = manifest.join("assets/tw.css");
    let output = manifest.join("assets/app.css");

    println!("cargo:rerun-if-changed=assets/tw.css");
    println!("cargo:rerun-if-changed=templates");
    println!("cargo:rerun-if-env-changed=RELAY_TAILWIND");

    if std::env::var("RELAY_TAILWIND").is_err() {
        return;
    }
    if !input.exists() {
        println!(
            "cargo:warning=RELAY_TAILWIND set but {} missing — skipping tailwind build",
            input.display()
        );
        return;
    }

    // Try npx first (Tailwind 4's recommended path), then the standalone binary.
    if try_run(&["npx", "@tailwindcss/cli"], &input, &output) {
        return;
    }
    if try_run(&["tailwindcss"], &input, &output) {
        return;
    }
    println!(
        "cargo:warning=tailwind not found. Install with `npm i -D tailwindcss @tailwindcss/cli` \
         or download the standalone binary from \
         https://github.com/tailwindlabs/tailwindcss/releases/latest"
    );
}

fn try_run(prefix: &[&str], input: &Path, output: &Path) -> bool {
    let (cmd, base_args) = prefix.split_first().expect("prefix non-empty");
    let mut c = Command::new(cmd);
    c.args(base_args);
    c.args(["-i", input.to_str().unwrap(), "-o", output.to_str().unwrap(), "--minify"]);
    match c.status() {
        Ok(s) if s.success() => {
            println!(
                "cargo:warning=tailwind ({}) regenerated {}",
                prefix.join(" "),
                output.display()
            );
            true
        }
        Ok(s) => {
            println!("cargo:warning=`{}` exited with {s}", prefix.join(" "));
            false
        }
        Err(_) => false, // binary not on PATH — silently try the next one
    }
}
