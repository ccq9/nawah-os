// Passes the build identity chosen by tools/project.py into the kernel (`env!("NAWAH_BUILD_ID")`).
fn main() {
    println!("cargo:rerun-if-env-changed=NAWAH_BUILD_ID");
    let id = std::env::var("NAWAH_BUILD_ID").unwrap_or_else(|_| "unknown".to_string());
    assert!(
        id.len() < 32 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "NAWAH_BUILD_ID must be short ASCII"
    );
    println!("cargo:rustc-env=NAWAH_BUILD_ID={id}");
    emit_apps();
}

/// Applications (WP-17): `NAWAH_APPS_DIR` names a directory with `<name>.elf` files built by
/// tools/project.py from user/apps; each becomes a byte slice in `apps.rs`. Without the
/// directory (plain `cargo check`), the slices are empty and the kernel reports the apps as
/// missing instead of failing to build. Test applications are only referenced by the test
/// kernel, hence `allow(dead_code)` on every slice.
const APPS: &[&str] = &[
    "hello",
    "file_roundtrip",
    "path_invalid",
    "fd_leak",
    "echo",
    "launch",
    "child",
    "waiter",
];

fn emit_apps() {
    println!("cargo:rerun-if-env-changed=NAWAH_APPS_DIR");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let dir = std::env::var("NAWAH_APPS_DIR")
        .ok()
        .map(std::path::PathBuf::from);
    let mut src = String::new();
    for name in APPS {
        let upper = name.to_uppercase();
        match dir.as_ref().map(|d| d.join(format!("{name}.elf"))) {
            Some(path) if path.is_file() => {
                println!("cargo:rerun-if-changed={}", path.display());
                src.push_str(&format!(
                    "#[allow(dead_code)]\npub static {upper}: &[u8] = include_bytes!({:?});\n",
                    path.canonicalize().expect("canonical app path")
                ));
            }
            _ => src.push_str(&format!(
                "#[allow(dead_code)]\npub static {upper}: &[u8] = &[];\n"
            )),
        }
    }
    std::fs::write(out.join("apps.rs"), src).expect("write apps.rs");
}
