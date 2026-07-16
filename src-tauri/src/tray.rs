use anyhow::Result;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, Runtime, WebviewUrl, WebviewWindowBuilder,
};

use crate::config::AppConfig;

pub fn create_tray<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
    let start = MenuItem::with_id(app, "start", "Start Proxy", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", "Stop Proxy", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &separator, &start, &stop, &separator, &quit])?;

    let icon = app.default_window_icon().cloned();
    
    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("stls - Disconnected");
    
    if let Some(ico) = icon {
        builder = builder.icon(Some(ico));
    }

    builder
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
        .on_tray_icon_event(move |tray, event| {
            if let TrayIconEvent::Click { button, button_state, .. } = event {
                if button == MouseButton::Left && button_state == MouseButtonState::Up {
                    let app = tray.app_handle();
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

pub fn create_main_window<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("stls - ShadowTLS Client")
        .inner_size(600.0, 700.0)
        .min_inner_size(500.0, 600.0)
        .resizable(true)
        .visible(true)
        .build()?;

    Ok(())
}