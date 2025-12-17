#![allow(missing_docs)]
#![allow(unsafe_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    prost_build::compile_protos(&["proto/aegis.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/aegis.proto");
    Ok(())
}
