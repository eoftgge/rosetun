#[path = "build/icon_res.rs"]
mod icon_res;

fn main() {
    println!("cargo:rerun-if-changed=assets/rosetun.ico");
    println!("cargo:rerun-if-changed=build/icon_res.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        println!("cargo:warning=the executable icon is embedded only with the MSVC toolchain");
        return;
    }

    let icon_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/rosetun.ico");
    let ico = std::fs::read(&icon_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", icon_path.display()));
    let resource = icon_res::icon_res(&ico)
        .unwrap_or_else(|error| panic!("invalid icon {}: {error}", icon_path.display()));
    let path = std::path::Path::new(&std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"))
        .join("rosetun.res");
    std::fs::write(&path, resource)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    // Only the GUI executable needs the icon, not its test binaries.
    println!("cargo:rustc-link-arg-bins={}", path.display());
}
