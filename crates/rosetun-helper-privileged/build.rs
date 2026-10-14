#[path = "../windows_resources.rs"]
mod windows_resources;

fn main() {
    println!("cargo:rerun-if-changed=../windows_resources.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        println!("cargo:warning=executable resources are embedded only with the MSVC toolchain");
        return;
    }

    let resource = windows_resources::executable_res(
        None,
        env!("CARGO_PKG_VERSION"),
        "Rosetun Service",
        "rosetun-helper-privileged.exe",
    )
    .unwrap_or_else(|error| panic!("invalid executable resource: {error}"));
    let path = std::path::Path::new(&std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"))
        .join("rosetun.res");
    std::fs::write(&path, resource)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    println!("cargo:rustc-link-arg-bins={}", path.display());
}
