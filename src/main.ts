import { invoke } from '@tauri-apps/api/core';

interface Config {
  server_address: string;
  ss_port: number;
  ss_password: string;
  stls_port: number;
  stls_password: string;
  stls_sni: string;
  socks5_port: number;
}

interface ProfileStore {
  profiles: { name: string; config: Config }[];
  active_profile: string;
}

async function updateStatus() {
  try {
    const isRunning = await invoke<boolean>('get_status');
    const dot = document.getElementById('status-dot')!;
    const text = document.getElementById('status-text')!;
    const btnStart = document.getElementById('btn-start') as HTMLButtonElement;
    const btnStop = document.getElementById('btn-stop') as HTMLButtonElement;

    if (isRunning) {
      dot.classList.add('connected');
      text.textContent = 'Connected';
      btnStart.disabled = true;
      btnStop.disabled = false;
    } else {
      dot.classList.remove('connected');
      text.textContent = 'Disconnected';
      btnStart.disabled = false;
      btnStop.disabled = true;
    }
  } catch (err) {
    showMessage('Status error: ' + err, 'error');
  }
}

async function startProxy() {
  try {
    const msg = await invoke<string>('start_proxy');
    showMessage(msg, 'success');
    await updateStatus();
  } catch (err) {
    showMessage('Failed: ' + err, 'error');
  }
}

async function stopProxy() {
  try {
    const msg = await invoke<string>('stop_proxy');
    showMessage(msg, 'success');
    await updateStatus();
  } catch (err) {
    showMessage('Failed: ' + err, 'error');
  }
}

async function openSettings() {
  try {
    await invoke('open_settings');
  } catch (err) {
    showMessage('Settings error: ' + err, 'error');
  }
}

function showMessage(text: string, type: 'success' | 'error') {
  const el = document.getElementById('message')!;
  el.textContent = text;
  el.className = 'message ' + type;
  setTimeout(() => { el.textContent = ''; el.className = 'message'; }, 5000);
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-start')?.addEventListener('click', startProxy);
  document.getElementById('btn-stop')?.addEventListener('click', stopProxy);
  document.getElementById('btn-settings')?.addEventListener('click', openSettings);
  updateStatus();
  setInterval(updateStatus, 2000);
});