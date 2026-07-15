//! stls - ShadowTLS Client for Windows

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod crypto;
mod proxy;
mod shadowtls;
mod shadowsocks;
mod tray;

use std::sync::Arc;
use tokio::sync::RwLock;

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, Runtime, WebviewUrl, WebviewWindowBuilder,
};

use crate::config::{AppConfig, Profile, ProxyStatus, ShadowTLSConfig, ShadowsocksConfig, TestResult};
use crate::proxy::{ProxyManager, test_connection};

struct AppState {
    proxy_manager: Arc<tokio::sync::Mutex<ProxyManager>>,
    config: Arc<RwLock<AppConfig>>,
    app_handle: Arc<tokio::sync::Mutex<Option<AppHandle>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            proxy_manager: Arc::new(tokio::sync::Mutex::new(ProxyManager::new())),
            config: Arc::new(RwLock::new(AppConfig::default())),
            app_handle: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

#[tauri::command]
async fn get_config(state: tauri::State<'_, AppState>) -> Result<AppConfig, String> {
    let config = state.config.read().await;
    Ok(config.clone())
}

#[tauri::command]
async fn save_config(state: tauri::State<'_, AppState>, config: AppConfig) -> Result<(), String> {
    let mut cfg = state.config.write().await;
    *cfg = config.clone();
    if let Some(handle) = state.app_handle.lock().await.as_ref() {
        if let Ok(store) = handle.store("config.json") {
            let _ = store.set("config", serde_json::to_value(&config).unwrap());
            let _ = store.save();
        }
    }
    Ok(())
}

#[tauri::command]
async fn get_profiles(state: tauri::State<'_, AppState>) -> Result<Vec<Profile>, String> {
    let config = state.config.read().await;
    Ok(config.profiles.clone())
}

#[tauri::command]
async fn add_profile(state: tauri::State<'_, AppState>, profile: Profile) -> Result<(), String> {
    let mut config = state.config.write().await;
    config.profiles.push(profile);
    save_config_to_store(&state, config.clone()).await
}

#[tauri::command]
async fn update_profile(state: tauri::State<'_, AppState>, index: usize, profile: Profile) -> Result<(), String> {
    let mut config = state.config.write().await;
    if index < config.profiles.len() {
        config.profiles[index] = profile;
        save_config_to_store(&state, config.clone()).await
    } else {
        Err("Profile index out of bounds".into())
    }
}

#[tauri::command]
async fn delete_profile(state: tauri::State<'_, AppState>, index: usize) -> Result<(), String> {
    let mut config = state.config.write().await;
    if index < config.profiles.len() {
        config.profiles.remove(index);
        save_config_to_store(&state, config.clone()).await
    } else {
        Err("Profile index out of bounds".into())
    }
}

#[tauri::command]
async fn import_profiles(state: tauri::State<'_, AppState>, profiles: Vec<Profile>) -> Result<(), String> {
    let mut config = state.config.write().await;
    config.profiles.extend(profiles);
    save_config_to_store(&state, config.clone()).await
}

async fn save_config_to_store(state: &tauri::State<'_, AppState>, config: AppConfig) -> Result<(), String> {
    if let Some(handle) = state.app_handle.lock().await.as_ref() {
        if let Ok(store) = handle.store("config.json") {
            let _ = store.set("config", serde_json::to_value(&config).unwrap());
            let _ = store.save();
        }
    }
    Ok(())
}

#[tauri::command]
async fn start_proxy(state: tauri::State<'_, AppState>, profile_index: usize) -> Result<(), String> {
    let config = state.config.read().await.clone();
    let profile = config.profiles.get(profile_index)
        .ok_or("Profile not found")?
        .clone();
    
    let mut proxy = state.proxy_manager.lock().await;
    proxy.start(profile).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn stop_proxy(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut proxy = state.proxy_manager.lock().await;
    proxy.stop().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_proxy_status(state: tauri::State<'_, AppState>) -> Result<ProxyStatus, String> {
    let proxy = state.proxy_manager.lock().await;
    Ok(proxy.status().await)
}

#[tauri::command]
async fn test_connection(state: tauri::State<'_, AppState>, profile_index: usize) -> Result<TestResult, String> {
    let config = state.config.read().await.clone();
    let profile = config.profiles.get(profile_index)
        .ok_or("Profile not found")?
        .clone();
    
    let result = test_connection(&profile).await;
    Ok(result)
}

#[tauri::command]
async fn parse_ss_uri(uri: String) -> Result<ShadowsocksConfig, String> {
    crate::shadowsocks::parse_ss_uri(&uri).map_err(|e| e.to_string())
}

#[tauri::command]
async fn parse_shadowtls_json(json: String) -> Result<ShadowTLSConfig, String> {
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

#[tauri::command]
async fn generate_ss_uri(config: ShadowsocksConfig) -> Result<String, String> {
    Ok(crate::shadowsocks::generate_ss_uri(&config))
}

#[tauri::command]
async fn generate_shadowtls_json(config: ShadowTLSConfig) -> Result<String, String> {
    Ok(serde_json::to_string_pretty(&config).unwrap())
}

#[tauri::command]
async fn show_window(app_handle: AppHandle) -> Result<(), String> {
    if let Some(window) = app_handle.get_webview_window("main") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn hide_window(app_handle: AppHandle) -> Result<(), String> {
    if let Some(window) = app_handle.get_webview_window("main") {
        window.hide().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn minimize_window(app_handle: AppHandle) -> Result<(), String> {
    if let Some(window) = app_handle.get_webview_window("main") {
        window.minimize().map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn create_tray<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
    let start = MenuItem::with_id(app, "start", "Start Proxy", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", "Stop Proxy", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &separator, &start, &stop, &separator, &quit])?;

    TrayIconBuilder::new()
        .icon(app.default_window_icon().cloned().unwrap())
        .menu(&menu)
        .tooltip("stls - Disconnected")
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "start" => {
                let _ = app.emit("tray-start-proxy", ());
            }
            "stop" => {
                let _ = app.emit("tray-stop-proxy", ());
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(move |app, event| {
            if let TrayIconEvent::Click { button, button_state, .. } = event {
                if button == MouseButton::Left && button_state == MouseButtonState::Up {
                    if let Some(window) = app.get_webview_window("main") {
                        let visible = window.is_visible().unwrap_or(false);
                        if visible {
                            let _ = window.hide();
                        } else {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }
            }
        })
        .build(app)?;

    Ok(())
}

async fn create_main_window<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("stls - ShadowTLS Client")
        .inner_size(600.0, 700.0)
        .min_inner_size(500.0, 600.0)
        .resizable(true)
        .visible(false)
        .build()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    let app_state = Arc::new(AppState::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_log::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .manage(app_state.clone())
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            get_profiles,
            add_profile,
            update_profile,
            delete_profile,
            import_profiles,
            start_proxy,
            stop_proxy,
            get_proxy_status,
            test_connection,
            parse_ss_uri,
            parse_shadowtls_json,
            generate_ss_uri,
            generate_shadowtls_json,
            show_window,
            hide_window,
            minimize_window,
        ])
        .setup(move |app| {
            let state = app_state.clone();
            *state.app_handle.lock().await = Some(app.handle().clone());

            // Load config from store
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Ok(store) = handle.store("config.json") {
                    let _ = store.load();
                    if let Some(value) = store.get("config") {
                        if let Ok(config) = serde_json::from_value::<AppConfig>(value.clone()) {
                            let mut state_config = state.config.write().await;
                            *state_config = config;
                            tracing::info!("Loaded config from store");
                        }
                    }
                }
            });

            // Create system tray
            create_tray(app.handle()).await?;

            // Create main window (hidden by default)
            create_main_window(app.handle()).await?;

            // Handle window close event - hide instead of quit
            if let Some(window) = app.get_webview_window("main") {
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                });
            }

            Ok(())
        })
        .run(tauri::generate_context!())?;

    Ok(())
}