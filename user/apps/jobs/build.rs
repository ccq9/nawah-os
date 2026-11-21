// Links the application at the fixed address the kernel's loader expects (user/link.ld) with
// every PT_LOAD segment on its own pages (W^X is then a property of whole pages).
fn main() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../link.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg-bins=-T{}", script.display());
    println!("cargo:rustc-link-arg-bins=-z");
    println!("cargo:rustc-link-arg-bins=separate-loadable-segments");
    println!("cargo:rustc-link-arg-bins=--no-dynamic-linker");
    // No RELRO split: the GOT stays in the one read-write segment (user/link.ld).
    println!("cargo:rustc-link-arg-bins=-z");
    println!("cargo:rustc-link-arg-bins=norelro");
}
