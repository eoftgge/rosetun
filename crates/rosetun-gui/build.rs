use std::io::Write;
use std::path::Path;

#[path = "../windows_resources.rs"]
mod windows_resources;

const BUNDLED_FONTS: &[&str] = &[
    "Manrope-Regular.ttf",
    "Manrope-SemiBold.ttf",
    "Noto-COLRv1.ttf",
    "CormorantGaramond-SemiBold.ttf",
];

fn compress_fonts(manifest_dir: &Path, out_dir: &Path) {
    for name in BUNDLED_FONTS {
        let rel = format!("assets/fonts/{name}");
        println!("cargo:rerun-if-changed={rel}");
        let source = manifest_dir.join(&rel);
        let raw = std::fs::read(&source)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()));
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder
            .write_all(&raw)
            .unwrap_or_else(|error| panic!("failed to compress {name}: {error}"));
        let compressed = encoder
            .finish()
            .unwrap_or_else(|error| panic!("failed to finish compressing {name}: {error}"));
        let target = out_dir.join(format!("{name}.zlib"));
        std::fs::write(&target, compressed)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", target.display()));
    }
}

fn main() {
    println!("cargo:rerun-if-changed=assets/rosetun.ico");
    println!("cargo:rerun-if-changed=../windows_resources.rs");

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_dir_os = std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo");
    let out_dir = Path::new(&out_dir_os);
    compress_fonts(manifest_dir, out_dir);

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        println!("cargo:warning=executable resources are embedded only with the MSVC toolchain");
        return;
    }

    let icon_path = manifest_dir.join("assets/rosetun.ico");
    let ico = std::fs::read(&icon_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", icon_path.display()));
    let resource = windows_resources::executable_res(
        Some(&ico),
        env!("CARGO_PKG_VERSION"),
        "Rosetun",
        "rosetun-gui.exe",
    )
    .unwrap_or_else(|error| panic!("invalid executable resource: {error}"));
    let path = out_dir.join("rosetun.res");
    std::fs::write(&path, resource)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    // Only the GUI executable needs the icon, not its test binaries.
    println!("cargo:rustc-link-arg-bins={}", path.display());
}
