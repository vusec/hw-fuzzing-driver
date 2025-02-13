use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=opcodes");

    // The RISC-V extensions that we should support.
    let extensions = [
        "rv_i", "rv_m", "rv_a", "rv_f", "rv_d", "rv64_i", "rv64_m", "rv64_a", "rv64_f", "rv64_d",
    ];

    let src_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    Command::new("python3")
        .current_dir(src_dir + "/opcodes")
        .args(["parse.py", "-rust_mutator"])
        .args(extensions)
        .status()
        .unwrap();
}
