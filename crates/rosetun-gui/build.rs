#[path = "../windows_resources.rs"]
mod windows_resources;

fn main() {
    println!("cargo:rerun-if-changed=assets/rosetun.ico");
    println!("cargo:rerun-if-changed=../windows_resources.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        println!("cargo:warning=executable resources are embedded only with the MSVC toolchain");
        return;
    }

    let icon_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/rosetun.ico");
    let ico = std::fs::read(&icon_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", icon_path.display()));
    let resource = windows_resources::executable_res(
        Some(&ico),
        env!("CARGO_PKG_VERSION"),
        "Rosetun",
        "rosetun-gui.exe",
    )
    .unwrap_or_else(|error| panic!("invalid executable resource: {error}"));
    let path = std::path::Path::new(&std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"))
        .join("rosetun.res");
    std::fs::write(&path, resource)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    // Only the GUI executable needs the icon, not its test binaries.
    println!("cargo:rustc-link-arg-bins={}", path.display());
}
