import { invoke } from '@tauri-apps/api/core';

interface Config {
  server_address: string;
  ss_port: number;
  ss_password: string;
  stls_port: number;
  stls_password: string;
  stls_sni: string;
  socks5_port: number;
  mtu: number;
  mode: string;
}

interface Profile {
  name: string;
  config: Config;
}

interface ProfileStore {
  profiles: Profile[];
  active_profile: string;
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

function fillForm(c: Config) {
  (document.getElementById('server_address') as HTMLInputElement).value = c.server_address;
  (document.getElementById('ss_port') as HTMLInputElement).value = c.ss_port.toString();
  (document.getElementById('ss_password') as HTMLInputElement).value = c.ss_password;
  (document.getElementById('stls_port') as HTMLInputElement).value = c.stls_port.toString();
  (document.getElementById('stls_password') as HTMLInputElement).value = c.stls_password;
  (document.getElementById('stls_sni') as HTMLInputElement).value = c.stls_sni;
  (document.getElementById('socks5_port') as HTMLInputElement).value = c.socks5_port.toString();
  (document.getElementById('mtu') as HTMLInputElement).value = c.mtu.toString();
}

function readForm(): Config {
  return {
    server_address: (document.getElementById('server_address') as HTMLInputElement).value,
    ss_port: parseInt((document.getElementById('ss_port') as HTMLInputElement).value, 10),
    ss_password: (document.getElementById('ss_password') as HTMLInputElement).value,
    stls_port: parseInt((document.getElementById('stls_port') as HTMLInputElement).value, 10),
    stls_password: (document.getElementById('stls_password') as HTMLInputElement).value,
    stls_sni: (document.getElementById('stls_sni') as HTMLInputElement).value,
    socks5_port: parseInt((document.getElementById('socks5_port') as HTMLInputElement).value, 10),
    mtu: parseInt((document.getElementById('mtu') as HTMLInputElement).value, 10) || 0,
    mode: '',
  };
}

async function loadProfiles() {
  try {
    const store = await invoke<ProfileStore>('get_profiles');
    const select = document.getElementById('profile-select') as HTMLSelectElement;
    select.innerHTML = '';
    store.profiles.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.name;
      opt.textContent = p.name;
      if (p.name === store.active_profile) opt.selected = true;
      select.appendChild(opt);
    });
    await loadConfig();
  } catch (err) {
    showMessage('Failed to load profiles: ' + err, 'error');
  }
}

async function loadConfig() {
  try {
    const config = await invoke<Config>('get_config');
    fillForm(config);
  } catch (err) {
    showMessage('Failed to load config: ' + err, 'error');
  }
}

async function saveConfig(event: Event) {
  event.preventDefault();
  const config = readForm();
  try {
    await invoke('save_config', { config });
    showMessage('Settings saved successfully!', 'success');
  } catch (err) {
    showMessage('Failed to save: ' + err, 'error');
  }
}

async function switchProfile() {
  const select = document.getElementById('profile-select') as HTMLSelectElement;
  const profileName = select.value;
  try {
    await invoke('switch_profile', { name: profileName });
    await loadConfig();
    showMessage('Switched to ' + profileName, 'success');
  } catch (err) {
    showMessage('Failed to switch: ' + err, 'error');
  }
}

async function newProfile() {
  const name = prompt('Enter profile name:');
  if (!name || name.trim() === '') return;
  const config = readForm();
  try {
    await invoke('add_profile', { name: name.trim(), config });
    await loadProfiles();
    showMessage('Profile created!', 'success');
  } catch (err) {
    showMessage('Failed to create: ' + err, 'error');
  }
}

async function deleteProfile() {
  const select = document.getElementById('profile-select') as HTMLSelectElement;
  const profileName = select.value;
  if (profileName === 'Default') {
    showMessage('Cannot delete Default profile', 'error');
    return;
  }
  if (!confirm(`Delete profile "${profileName}"?`)) return;
  try {
    await invoke('delete_profile', { name: profileName });
    await loadProfiles();
    showMessage('Profile deleted', 'success');
  } catch (err) {
    showMessage('Failed to delete: ' + err, 'error');
  }
}

function closeWindow() {
  window.close();
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('settings-form')?.addEventListener('submit', saveConfig);
  document.getElementById('btn-back')?.addEventListener('click', closeWindow);
  document.getElementById('profile-select')?.addEventListener('change', switchProfile);
  document.getElementById('btn-new-profile')?.addEventListener('click', newProfile);
  document.getElementById('btn-delete-profile')?.addEventListener('click', deleteProfile);
  loadProfiles();
});
