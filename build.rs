use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn find_protos(dir: &str) -> Result<Vec<String>, std::io::Error> {
    let mut protos = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("proto") {
            protos.push(path.to_string_lossy().into_owned());
        } else if path.is_dir() {
            protos.extend(find_protos(path.to_str().unwrap())?);
        }
    }
    Ok(protos)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let build_timestamp = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        });
    println!(
        "cargo:rustc-env=CLOUD_NODE_BUILD_TIMESTAMP={}",
        build_timestamp
    );

    let proto_dir = "proto_defs/output_protos";
    let models_dir = "proto_defs/output_protos/models";

    if std::path::Path::new(proto_dir).exists() {
        let protos = find_protos(proto_dir)?;

        println!("cargo:rerun-if-changed={}", proto_dir);

        // Compile with configure
        tonic_build::configure()
            .build_server(false)
            .compile_protos(&protos, &[proto_dir, models_dir])?;
    }
    Ok(())
}
