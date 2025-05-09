use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("fabric-protos");

    if !proto_dir.exists() {
        panic!(
            "Fabric Proto directory does not exist: {:?} Did you initialize the git submodules?",
            proto_dir
        );
    }

    // Find all .proto files in the repository
    let proto_files = find_proto_files(&proto_dir);

    let mut config = tonic_build::Config::new();
    config.out_dir("src/protos");

    tonic_build::configure()
        .build_client(true)
        .compile_protos_with_config(config, &proto_files, &[proto_dir])?;
    Ok(())
}
fn find_proto_files(dir: &Path) -> Vec<PathBuf> {
    let mut proto_files = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();

            if path.is_dir() {
                // Recursively search subdirectories
                proto_files.extend(find_proto_files(&path));
            } else if path.extension().map_or(false, |ext| ext == "proto") {
                proto_files.push(path);
            }
        }
    }

    proto_files
}
