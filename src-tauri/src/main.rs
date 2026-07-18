// main.rs - Tauri app entry with commands
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::{Manager, State, WebviewUrl, WebviewWindowBuilder};

mod config;
mod proxy;

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
    store.add_profile(name.clone(), config).map_err(|e| e.to_string())?;
    Ok(format!("Profile '{}' added", name))
}

#[tauri::command]
fn delete_profile(name: String) -> Result<String, String> {
    let mut store = ProfileStore::load().map_err(|e| e.to_string())?;
    store.delete_profile(&name).map_err(|e| e.to_string())?;
    Ok(format!("Profile '{}' deleted", name))
}

#[tauri::command]
fn switch_profile(name: String) -> Result<String, String> {
    let mut store = ProfileStore::load().map_err(|e| e.to_string())?;
    store.switch_profile(&name).map_err(|e| e.to_string())?;
    Ok(format!("Switched to profile '{}'", name))
}

fn create_main_window(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("stls v5")
        .inner_size(500.0, 400.0)
        .resizable(false)
        .build()?;
    Ok(())
}

#[tauri::command]
fn open_settings_window(app: tauri::AppHandle) -> Result<(), String> {
    tauri::WebviewWindowBuilder::new(&app, "settings", WebviewUrl::App("settings.html".into()))
        .title("stls v2 Settings")
        .inner_size(600.0, 500.0)
        .resizable(true)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
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
            open_settings_window,
        ])
        .run(tauri::generate_context!())
        .expect("error running tauri app");
}
