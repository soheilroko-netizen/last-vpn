import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';

interface Config {
  server_address: string;
  server_port: number;
  password: string;
  shadowtls_password: string;
  socks5_port: number;
}

async function loadConfig() {
  try {
    const config = await invoke<Config>('get_config');
    (document.getElementById('server_address') as HTMLInputElement).value = config.server_address;
    (document.getElementById('server_port') as HTMLInputElement).value = config.server_port.toString();
    (document.getElementById('password') as HTMLInputElement).value = config.password;
    (document.getElementById('shadowtls_password') as HTMLInputElement).value = config.shadowtls_password;
    (document.getElementById('socks5_port') as HTMLInputElement).value = config.socks5_port.toString();
  } catch (err) {
    showMessage('Failed to load config: ' + err, 'error');
  }
}

async function saveConfig(event: Event) {
  event.preventDefault();
  
  const config: Config = {
    server_address: (document.getElementById('server_address') as HTMLInputElement).value,
    server_port: parseInt((document.getElementById('server_port') as HTMLInputElement).value),
    password: (document.getElementById('password') as HTMLInputElement).value,
    shadowtls_password: (document.getElementById('shadowtls_password') as HTMLInputElement).value,
    socks5_port: parseInt((document.getElementById('socks5_port') as HTMLInputElement).value),
  };

  try {
    const msg = await invoke<string>('save_config', { config });
    showMessage(msg, 'success');
  } catch (err) {
    showMessage('Failed to save: ' + err, 'error');
  }
}

function showMessage(text: string, type: 'success' | 'error') {
  const msgEl = document.getElementById('message')!;
  msgEl.textContent = text;
  msgEl.className = `message ${type}`;
  setTimeout(() => {
    msgEl.textContent = '';
    msgEl.className = 'message';
  }, 5000);
}

function goBack() {
  const webview = getCurrentWebviewWindow();
  webview.emit('navigate', { page: 'index.html' });
  window.location.href = 'index.html';
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('settings-form')?.addEventListener('submit', saveConfig);
  document.getElementById('btn-back')?.addEventListener('click', goBack);
  loadConfig();
});
