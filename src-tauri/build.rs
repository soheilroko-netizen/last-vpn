fn main() {
    // Embed manifest for admin elevation (requireAdministrator)
    embed_resource::compile("stls.exe.manifest", embed_resource::args::StandardArgs::new())
        .expect("failed to embed manifest");
    tauri_build::build()
}
