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

interface Profile {
  name: string;
  config: Config;
}

interface ProfileStore {
  profiles: Profile[];
  active_profile: string;
}

// View switching — Settings opens in its own window
function showMainView() {
  document.getElementById('main-view')!.style.display = 'block';
  document.getElementById('settings-view')!.style.display = 'none';
}

async function showSettingsView() {
  await invoke('open_settings_window');
}

async function updateStatus() {
  try {
    const isRunning = await invoke<boolean>('get_status');
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

// Settings functions
async function loadProfiles() {
  try {
    const store = await invoke<ProfileStore>('get_profiles');
    const select = document.getElementById('profile-select') as HTMLSelectElement;
    select.innerHTML = '';
    
    store.profiles.forEach(profile => {
      const option = document.createElement('option');
      option.value = profile.name;
      option.textContent = profile.name;
      if (profile.name === store.active_profile) {
        option.selected = true;
      }
      select.appendChild(option);
    });
    
    await loadConfig();
  } catch (err) {
    showSettingsMessage('Failed to load profiles: ' + err, 'error');
  }
}

async function loadConfig() {
  try {
    const config = await invoke<Config>('get_config');
    (document.getElementById('server_address') as HTMLInputElement).value = config.server_address;
    (document.getElementById('ss_port') as HTMLInputElement).value = config.ss_port.toString();
    (document.getElementById('ss_password') as HTMLInputElement).value = config.ss_password;
    (document.getElementById('stls_port') as HTMLInputElement).value = config.stls_port.toString();
    (document.getElementById('stls_password') as HTMLInputElement).value = config.stls_password;
    (document.getElementById('stls_sni') as HTMLInputElement).value = config.stls_sni;
    (document.getElementById('socks5_port') as HTMLInputElement).value = config.socks5_port.toString();
  } catch (err) {
    showSettingsMessage('Failed to load config: ' + err, 'error');
  }
}

async function saveConfig(event: Event) {
  event.preventDefault();
  
  const config: Config = {
    server_address: (document.getElementById('server_address') as HTMLInputElement).value,
    ss_port: parseInt((document.getElementById('ss_port') as HTMLInputElement).value),
    ss_password: (document.getElementById('ss_password') as HTMLInputElement).value,
    stls_port: parseInt((document.getElementById('stls_port') as HTMLInputElement).value),
    stls_password: (document.getElementById('stls_password') as HTMLInputElement).value,
    stls_sni: (document.getElementById('stls_sni') as HTMLInputElement).value,
    socks5_port: parseInt((document.getElementById('socks5_port') as HTMLInputElement).value),
  };

  try {
    await invoke('save_config', { config });
    showSettingsMessage('Settings saved successfully!', 'success');
    setTimeout(() => showMainView(), 1500);
  } catch (err) {
    showSettingsMessage('Failed to save: ' + err, 'error');
  }
}

async function switchProfile() {
  const select = document.getElementById('profile-select') as HTMLSelectElement;
  const profileName = select.value;
  
  try {
    await invoke('switch_profile', { name: profileName });
    await loadConfig();
    showSettingsMessage('Switched to ' + profileName, 'success');
  } catch (err) {
    showSettingsMessage('Failed to switch: ' + err, 'error');
  }
}

async function newProfile() {
  const name = prompt('Enter profile name:');
  if (!name || name.trim() === '') return;
  
  const config: Config = {
    server_address: (document.getElementById('server_address') as HTMLInputElement).value,
    ss_port: parseInt((document.getElementById('ss_port') as HTMLInputElement).value),
    ss_password: (document.getElementById('ss_password') as HTMLInputElement).value,
    stls_port: parseInt((document.getElementById('stls_port') as HTMLInputElement).value),
    stls_password: (document.getElementById('stls_password') as HTMLInputElement).value,
    stls_sni: (document.getElementById('stls_sni') as HTMLInputElement).value,
    socks5_port: parseInt((document.getElementById('socks5_port') as HTMLInputElement).value),
  };
  
  try {
    await invoke('add_profile', { name: name.trim(), config });
    await loadProfiles();
    showSettingsMessage('Profile created!', 'success');
  } catch (err) {
    showSettingsMessage('Failed to create: ' + err, 'error');
  }
}

async function deleteProfile() {
  const select = document.getElementById('profile-select') as HTMLSelectElement;
  const profileName = select.value;
  
  if (profileName === 'Default') {
    showSettingsMessage('Cannot delete Default profile', 'error');
    return;
  }
  
  if (!confirm(`Delete profile "${profileName}"?`)) return;
  
  try {
    await invoke('delete_profile', { name: profileName });
    await loadProfiles();
    showSettingsMessage('Profile deleted', 'success');
  } catch (err) {
    showSettingsMessage('Failed to delete: ' + err, 'error');
  }
}

function showSettingsMessage(text: string, type: 'success' | 'error') {
  const msgEl = document.getElementById('settings-message')!;
  msgEl.textContent = text;
  msgEl.className = `message ${type}`;
  setTimeout(() => {
    msgEl.textContent = '';
    msgEl.className = 'message';
  }, 3000);
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-start')?.addEventListener('click', startProxy);
  document.getElementById('btn-stop')?.addEventListener('click', stopProxy);
  document.getElementById('btn-settings')?.addEventListener('click', showSettingsView);
  document.getElementById('btn-back')?.addEventListener('click', showMainView);
  document.getElementById('settings-form')?.addEventListener('submit', saveConfig);
  document.getElementById('profile-select')?.addEventListener('change', switchProfile);
  document.getElementById('btn-new-profile')?.addEventListener('click', newProfile);
  document.getElementById('btn-delete-profile')?.addEventListener('click', deleteProfile);
  updateStatus();
  setInterval(updateStatus, 2000);
});
