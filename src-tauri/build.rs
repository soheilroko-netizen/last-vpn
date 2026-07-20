fn main() {
    embed_resource::compile("stls.rc");
    tauri_build::build()
}
