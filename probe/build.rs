#![allow(missing_docs)]

fn main() {
    println!("cargo:rerun-if-env-changed=AEGIS_UNSIGNED_RELEASE");

    let Ok(val) = std::env::var("AEGIS_UNSIGNED_RELEASE") else {
        return;
    };

    let val = val.trim().to_ascii_lowercase();
    if val == "1" || val == "true" || val == "yes" {
        println!("cargo:rustc-env=AEGIS_IS_UNSIGNED_BUILD=1");
    }
}
