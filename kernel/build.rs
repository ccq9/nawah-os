// Passes the build identity chosen by tools/project.py into the kernel (`env!("NAWAH_BUILD_ID")`).
fn main() {
    println!("cargo:rerun-if-env-changed=NAWAH_BUILD_ID");
    let id = std::env::var("NAWAH_BUILD_ID").unwrap_or_else(|_| "unknown".to_string());
    assert!(
        id.len() < 32 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "NAWAH_BUILD_ID must be short ASCII"
    );
    println!("cargo:rustc-env=NAWAH_BUILD_ID={id}");
}
