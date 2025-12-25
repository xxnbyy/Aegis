#![allow(missing_docs)]

fn truthy(val: &str) -> bool {
    let val = val.trim().to_ascii_lowercase();
    val == "1" || val == "true" || val == "yes"
}

fn main() {
    println!("cargo:rerun-if-env-changed=AEGIS_UNSIGNED_RELEASE");
    println!("cargo:rerun-if-env-changed=AEGIS_ORG_PUBKEY_PATH");
    println!("cargo:rerun-if-env-changed=AEGIS_SELF_ED25519_PUBKEY_PATH");

    let unsigned = std::env::var("AEGIS_UNSIGNED_RELEASE")
        .ok()
        .is_some_and(|v| truthy(v.as_str()));

    if unsigned {
        println!("cargo:rustc-env=AEGIS_IS_UNSIGNED_BUILD=1");
    }

    let embedded_key_path = if unsigned {
        None
    } else {
        std::env::var_os("AEGIS_ORG_PUBKEY_PATH").map(std::path::PathBuf::from)
    };

    let out_dir = std::env::var_os("OUT_DIR").map(std::path::PathBuf::from);
    let Some(out_dir) = out_dir else {
        println!("cargo:warning=missing OUT_DIR");
        std::process::exit(1);
    };
    let out_path = out_dir.join("embedded_org_pubkey.rs");
    let out_ed25519_path = out_dir.join("embedded_self_ed25519_pubkey.rs");

    let contents = match embedded_key_path {
        None => "pub const EMBEDDED_ORG_PUBKEY_DER: Option<&'static [u8]> = None;\n".to_string(),
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = match std::fs::read(path.as_path()) {
                Ok(b) => b,
                Err(e) => {
                    println!(
                        "cargo:warning=failed to read AEGIS_ORG_PUBKEY_PATH {}: {}",
                        path.display(),
                        e
                    );
                    std::process::exit(1);
                }
            };
            format!(
                "pub const EMBEDDED_ORG_PUBKEY_DER: Option<&'static [u8]> = Some(&{bytes:?});\n"
            )
        }
    };

    if let Err(e) = std::fs::write(out_path.as_path(), contents.as_bytes()) {
        println!(
            "cargo:warning=failed to write embedded_org_pubkey.rs {}: {}",
            out_path.display(),
            e
        );
        std::process::exit(1);
    }

    let embedded_ed25519_key_path = if unsigned {
        None
    } else {
        std::env::var_os("AEGIS_SELF_ED25519_PUBKEY_PATH").map(std::path::PathBuf::from)
    };

    let ed25519_contents = match embedded_ed25519_key_path {
        None => {
            "pub const EMBEDDED_SELF_ED25519_PUBKEY: Option<&'static [u8]> = None;\n".to_string()
        }
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = match std::fs::read(path.as_path()) {
                Ok(b) => b,
                Err(e) => {
                    println!(
                        "cargo:warning=failed to read AEGIS_SELF_ED25519_PUBKEY_PATH {}: {}",
                        path.display(),
                        e
                    );
                    std::process::exit(1);
                }
            };
            format!(
                "pub const EMBEDDED_SELF_ED25519_PUBKEY: Option<&'static [u8]> = Some(&{bytes:?});\n"
            )
        }
    };

    if let Err(e) = std::fs::write(out_ed25519_path.as_path(), ed25519_contents.as_bytes()) {
        println!(
            "cargo:warning=failed to write embedded_self_ed25519_pubkey.rs {}: {}",
            out_ed25519_path.display(),
            e
        );
        std::process::exit(1);
    }
}
