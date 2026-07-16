import { invoke } from '@tauri-apps/api/core';

let isRunning = false;

async function updateStatus() {
  try {
    isRunning = await invoke<boolean>('get_status');
    const statusDot = document.getElementById('status-dot')!;
    const statusText = document.getElementById('status-text')!;
    const btnStart = document.getElementById('btn-start') as HTMLButtonElement;
    const btnStop = document.getElementById('btn-stop') as HTMLButtonElement;

    if (isRunning) {
      statusDot.classList.add('connected');
      statusText.textContent = 'Connected';
      btnStart.disabled = true;
      btnStop.disabled = false;
    } else {
      statusDot.classList.remove('connected');
      statusText.textContent = 'Disconnected';
      btnStart.disabled = false;
      btnStop.disabled = true;
    }
  } catch (err) {
    showMessage('Error checking status: ' + err, 'error');
  }
}

async function startProxy() {
  try {
    const msg = await invoke<string>('start_proxy');
    showMessage(msg, 'success');
    await updateStatus();
  } catch (err) {
    showMessage('Failed to start: ' + err, 'error');
  }
}

async function stopProxy() {
  try {
    const msg = await invoke<string>('stop_proxy');
    showMessage(msg, 'success');
    await updateStatus();
  } catch (err) {
    showMessage('Failed to stop: ' + err, 'error');
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

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-start')?.addEventListener('click', startProxy);
  document.getElementById('btn-stop')?.addEventListener('click', stopProxy);
  updateStatus();
});
