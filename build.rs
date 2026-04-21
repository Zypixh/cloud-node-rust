use std::fs;

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
