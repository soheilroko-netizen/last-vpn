// main.rs - Tauri app entry with commands
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::{Manager, State, WebviewUrl, WebviewWindowBuilder};

mod config;
mod proxy;
mod sysproxy;

use config::Config;
use config::ProfileStore;
use proxy::ProxyManager;

struct AppState {
    proxy: Mutex<ProxyManager>,
}

#[tauri::command]
fn get_status(state: State<AppState>) -> Result<bool, String> {
    let proxy = state.proxy.lock().unwrap();
    Ok(proxy.is_running())
}

#[tauri::command]
fn start_proxy(state: State<AppState>) -> Result<String, String> {
    let mut proxy = state.proxy.lock().unwrap();
    proxy.start().map_err(|e| e.to_string())
}

#[tauri::command]
fn stop_proxy(state: State<AppState>) -> Result<String, String> {
    let mut proxy = state.proxy.lock().unwrap();
    proxy.stop().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_config() -> Result<Config, String> {
    Config::load().map_err(|e| e.to_string())
}

#[tauri::command]
fn save_config(config: Config) -> Result<String, String> {
    config.save().map_err(|e| e.to_string())?;
    Ok("Configuration saved".to_string())
}

#[tauri::command]
fn get_profiles() -> Result<ProfileStore, String> {
    ProfileStore::load().map_err(|e| e.to_string())
}

#[tauri::command]
fn add_profile(name: String, config: Config) -> Result<String, String> {
    let mut store = ProfileStore::load().map_err(|e| e.to_string())?;
    store
        .add_profile(name.clone(), config)
        .map_err(|e| e.to_string())?;
    Ok(format!("Profile '{}' added", name))
}

#[tauri::command]
fn delete_profile(name: String) -> Result<String, String> {
    let mut store = ProfileStore::load().map_err(|e| e.to_string())?;
    store
        .delete_profile(&name)
        .map_err(|e| e.to_string())?;
    Ok(format!("Profile '{}' deleted", name))
}

#[tauri::command]
fn switch_profile(name: String) -> Result<String, String> {
    let mut store = ProfileStore::load().map_err(|e| e.to_string())?;
    store
        .switch_profile(&name)
        .map_err(|e| e.to_string())?;
    Ok(format!("Switched to profile '{}'", name))
}

#[tauri::command]
fn get_debug_log(state: State<AppState>) -> Result<String, String> {
    let proxy = state.proxy.lock().unwrap();
    let path = &proxy.debug_log_path;
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

fn create_main_window(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("stls v5")
        .inner_size(500.0, 480.0)
        .resizable(true)
        .build()?;
    Ok(())
}

fn main() {
    // Log panics to file for debugging silent crashes
    let panic_log = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("stls-panic.log");
    std::fs::write(&panic_log, "stls starting...\n").ok();
    let pl = panic_log.clone();
    std::panic::set_hook(Box::new(move |info| {
        let msg = format!("PANIC: {}\n", info);
        std::fs::write(&pl, &msg).ok();
    }));

    let proxy_manager = ProxyManager::new().expect("Failed to init proxy manager");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            proxy: Mutex::new(proxy_manager),
        })
        .setup(|app| {
            create_main_window(&app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_proxy,
            stop_proxy,
            get_config,
            save_config,
            get_profiles,
            add_profile,
            delete_profile,
            switch_profile,
            get_debug_log,
        ])
        .run(tauri::generate_context!())
        .expect("error running tauri app");
}
