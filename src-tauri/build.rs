fn main() {
    // Embed manifest via embedded resource .rc file
    embed_resource::compile("stls.rc");
    tauri_build::build()
}
