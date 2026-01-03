fn main() {
    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    config
        .compile_protos(&["proto/et.proto", "proto/eterminal.proto"], &["proto/"])
        .expect("Failed to compile protobuf files");
}
