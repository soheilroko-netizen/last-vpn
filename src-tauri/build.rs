fn main() {
    // Embed manifest for admin elevation (requireAdministrator)
    embed_resource::compile("stls.exe.manifest");
    tauri_build::build()
}
