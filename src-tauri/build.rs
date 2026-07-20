fn main() {
    embed_resource::compile("stls.rc", &[] as &[&str]);
    tauri_build::build()
}
