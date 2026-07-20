fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("stls.exe.manifest");
        res.compile()
            .expect("failed to embed manifest");
    }
    tauri_build::build()
}
