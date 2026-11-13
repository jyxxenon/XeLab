fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = "../../docs/contracts/proto";
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_build::configure().compile_protos(
        &[
            format!("{root}/xelab/v1/lifecycle.proto"),
            format!("{root}/xelab/v1/capability.proto"),
            format!("{root}/xelab/v1/host.proto"),
            format!("{root}/xelab/v1/migration.proto"),
        ],
        &[root.to_string()],
    )?;
    println!("cargo:rerun-if-changed={root}");
    Ok(())
}
