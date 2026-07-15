import './styles.css';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
interface ShadowsocksConfig {
  cipher: string;
  password: string;
  server: string;
  port: number;
  plugin?: string;
  plugin_opts?: string;
}

interface ShadowTLSConfig {
  server: string;
  server_port: number;
  version: number;
  password: string;
  tls: {
    enabled: boolean;
    server_name: string;
    insecure: boolean;
  };
}

interface Profile {
  name: string;
  shadowsocks: ShadowsocksConfig;
  shadowtls: ShadowTLSConfig;
  local_socks_port: number;
}

interface AppConfig {
  profiles: Profile[];
  settings: {
    auto_start: boolean;
    minimize_to_tray: boolean;
    log_level: string;
  };
}

interface ProxyStatus {
  state: 'Stopped' | 'Starting' | 'Running' | 'Error';
  profile?: string;
  local_port?: number;
  error?: string;
}

interface TestResult {
  success: boolean;
  latency_ms?: number;
  error?: string;
}

const CIPHERS = [
  '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305',
  'aes-256-gcm',
  'aes-128-gcm',
  'chacha20-ietf-poly1305',
];

let currentConfig: AppConfig = { profiles: [], settings: { auto_start: false, minimize_to_tray: true, log_level: 'info' } };
let currentStatus: ProxyStatus = { state: 'Stopped' };
let selectedProfileIndex = -1;

const $ = (sel: string) => document.querySelector(sel)!;
const $$ = (sel: string) => document.querySelectorAll(sel);

// Tabs
function initTabs() {
  $$('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('.tab').forEach(t => t.classList.remove('active'));
      $$('.tab-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      ($(`#panel-${(tab as HTMLElement).dataset.tab}`) as HTMLElement)?.classList.add('active');
    });
  });
}

// Status badge
function renderStatus(status: ProxyStatus) {
  const el = $('#status-badge') as HTMLElement;
  let className = 'status-badge status-stopped';
  let text = 'Stopped';
  let dot = true;

  switch (status.state) {
    case 'Starting':
      className = 'status-badge status-starting';
      text = 'Starting...';
      break;
    case 'Running':
      className = 'status-badge status-running';
      text = `Running on 127.0.0.1:${status.local_port}`;
      break;
    case 'Error':
      className = 'status-badge status-error';
      text = `Error: ${status.error}`;
      break;
  }

  el.className = className;
  el.innerHTML = `${dot ? '<span class="status-dot"></span>' : ''}${text}`;
}

// Profile list
function renderProfiles() {
  const container = $('#profile-list') as HTMLElement;
  if (currentConfig.profiles.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M19 21V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v5m-4 0h4"/>
        </svg>
        <p>No profiles yet</p>
        <button class="btn btn-primary mt-8" onclick="document.getElementById('add-profile-btn').click()">Add Profile</button>
      </div>
    `;
    return;
  }

  container.innerHTML = currentConfig.profiles.map((p, i) => `
    <div class="profile-item ${i === selectedProfileIndex ? 'active' : ''}" data-index="${i}">
      <div class="profile-info">
        <div class="profile-name">${escapeHtml(p.name)}</div>
        <div class="profile-details">
          ${p.shadowsocks.cipher} • ${p.shadowtls.server}:${p.shadowtls.server_port} • SOCKS5: ${p.local_socks_port}
        </div>
      </div>
      <div class="profile-actions">
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); testProfile(${i})" title="Test">▶</button>
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); editProfile(${i})" title="Edit">✎</button>
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); deleteProfile(${i})" title="Delete">🗑</button>
      </div>
    </div>
  `).join('');

  $$('.profile-item').forEach(item => {
    item.addEventListener('click', () => {
      selectedProfileIndex = parseInt((item as HTMLElement).dataset.index!);
      renderProfiles();
      showProfileDetails(selectedProfileIndex);
    });
  });
}

function showProfileDetails(index: number) {
  const p = currentConfig.profiles[index];
  const panel = $('#profile-details') as HTMLElement;
  panel.innerHTML = `
    <div class="section-title">Profile Details</div>
    <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); line-height: 1.8;">
      <strong>Name:</strong> ${escapeHtml(p.name)}<br>
      <strong>SOCKS5 Port:</strong> ${p.local_socks_port}<br><br>
      <strong>Shadowsocks:</strong><br>
      &nbsp;&nbsp;Cipher: ${p.shadowsocks.cipher}<br>
      &nbsp;&nbsp;Password: ${'*'.repeat(p.shadowsocks.password.length)}<br>
      &nbsp;&nbsp;Server: ${p.shadowsocks.server}:${p.shadowsocks.port}<br><br>
      <strong>ShadowTLS:</strong><br>
      &nbsp;&nbsp;Version: ${p.shadowtls.version}<br>
      &nbsp;&nbsp;Server: ${p.shadowtls.server}:${p.shadowtls.server_port}<br>
      &nbsp;&nbsp;Password: ${'*'.repeat(p.shadowtls.password.length)}<br>
      &nbsp;&nbsp;SNI: ${p.shadowtls.tls.server_name}<br>
      &nbsp;&nbsp;TLS Enabled: ${p.shadowtls.tls.enabled ? 'Yes' : 'No'}
    </div>
  `;
}

// Form handling
function openProfileModal(profile?: Profile, index?: number) {
  const modal = $('#profile-modal') as HTMLDialogElement;
  const form = $('#profile-form') as HTMLFormElement;
  form.reset();

  if (profile) {
    ($('#p-name') as HTMLInputElement).value = profile.name;
    ($('#p-cipher') as HTMLSelectElement).value = profile.shadowsocks.cipher;
    ($('#p-ss-password') as HTMLInputElement).value = profile.shadowsocks.password;
    ($('#p-stls-server') as HTMLInputElement).value = profile.shadowtls.server;
    ($('#p-stls-port') as HTMLInputElement).value = profile.shadowtls.server_port.toString();
    ($('#p-stls-version') as HTMLSelectElement).value = profile.shadowtls.version.toString();
    ($('#p-stls-password') as HTMLInputElement).value = profile.shadowtls.password;
    ($('#p-stls-sni') as HTMLInputElement).value = profile.shadowtls.tls.server_name;
    ($('#p-local-port') as HTMLInputElement).value = profile.local_socks_port.toString();
    form.dataset.editIndex = index!.toString();
    ($('#modal-title') as HTMLElement).textContent = 'Edit Profile';
  } else {
    delete form.dataset.editIndex;
    ($('#modal-title') as HTMLElement).textContent = 'Add Profile';
    ($('#p-cipher') as HTMLSelectElement).value = '2022-blake3-chacha20-poly1305';
    ($('#p-stls-version') as HTMLSelectElement).value = '3';
    ($('#p-stls-sni') as HTMLInputElement).value = 'dl.google.com';
    ($('#p-local-port') as HTMLInputElement).value = '1080';
  }

  modal.showModal();
}

function closeProfileModal() {
  ($('#profile-modal') as HTMLDialogElement).close();
}

async function saveProfile(e: Event) {
  e.preventDefault();
  const form = e.target as HTMLFormElement;
  const editIndex = form.dataset.editIndex ? parseInt(form.dataset.editIndex) : null;

  const profile: Profile = {
    name: ($('#p-name') as HTMLInputElement).value.trim(),
    shadowsocks: {
      cipher: ($('#p-cipher') as HTMLSelectElement).value,
      password: ($('#p-ss-password') as HTMLInputElement).value,
      server: 'auto',
      port: 0,
      plugin: undefined,
      plugin_opts: undefined,
    },
    shadowtls: {
      server: ($('#p-stls-server') as HTMLInputElement).value.trim(),
      server_port: parseInt(($('#p-stls-port') as HTMLInputElement).value),
      version: parseInt(($('#p-stls-version') as HTMLSelectElement).value),
      password: ($('#p-stls-password') as HTMLInputElement).value,
      tls: {
        enabled: true,
        server_name: ($('#p-stls-sni') as HTMLInputElement).value.trim(),
        insecure: false,
      },
    },
    local_socks_port: parseInt(($('#p-local-port') as HTMLInputElement).value),
  };

  if (!profile.name || !profile.shadowsocks.password || !profile.shadowtls.server || !profile.shadowtls.password) {
    alert('Please fill all required fields');
    return;
  }

  if (editIndex !== null) {
    currentConfig.profiles[editIndex] = profile;
  } else {
    currentConfig.profiles.push(profile);
  }

  await saveConfig();
  closeProfileModal();
  renderProfiles();
}

async function editProfile(index: number) {
  openProfileModal(currentConfig.profiles[index], index);
}

async function deleteProfile(index: number) {
  if (!confirm('Delete this profile?')) return;
  currentConfig.profiles.splice(index, 1);
  if (selectedProfileIndex >= index) selectedProfileIndex = -1;
  await saveConfig();
  renderProfiles();
}

async function testProfile(index: number) {
  const btn = $(`.profile-item[data-index="${index}"] .btn`) as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = '...';

  try {
    const result: TestResult = await invoke('test_connection', { profileIndex: index });
    if (result.success) {
      btn.textContent = `✓ ${result.latency_ms}ms`;
      btn.classList.add('btn-primary');
      setTimeout(() => { btn.textContent = '▶'; btn.classList.remove('btn-primary'); }, 2000);
    } else {
      btn.textContent = '✗';
      setTimeout(() => { btn.textContent = '▶'; }, 2000);
    }
  } catch (err) {
    btn.textContent = '✗';
    setTimeout(() => { btn.textContent = '▶'; }, 2000);
  } finally {
    btn.disabled = false;
  }
}

// Import/Export
async function exportProfiles() {
  const data = JSON.stringify(currentConfig.profiles, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `stls-profiles-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function importProfiles(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (!file) return;
  const text = await file.text();
  try {
    const profiles = JSON.parse(text);
    if (Array.isArray(profiles)) {
      currentConfig.profiles.push(...profiles);
      await saveConfig();
      renderProfiles();
      alert(`Imported ${profiles.length} profiles`);
    }
  } catch {
    alert('Invalid JSON file');
  }
  (e.target as HTMLInputElement).value = '';
}

// Parse SS URI
async function parseSsUri() {
  const uri = ($('#ss-uri-input') as HTMLInputElement).value.trim();
  if (!uri) return alert('Paste a Shadowsocks URI');

  try {
    const config: ShadowsocksConfig = await invoke('parse_ss_uri', { uri });
    ($('#p-cipher') as HTMLSelectElement).value = config.cipher;
    ($('#p-ss-password') as HTMLInputElement).value = config.password;
    alert(`Parsed: ${config.cipher} • ${config.password.slice(0,8)}...`);
  } catch (err) {
    alert('Failed to parse URI: ' + err);
  }
}

async function parseStlsJson() {
  const json = ($('#stls-json-input') as HTMLTextAreaElement).value.trim();
  if (!json) return alert('Paste ShadowTLS JSON');

  try {
    const config: ShadowTLSConfig = await invoke('parse_shadowtls_json', { json });
    ($('#p-stls-server') as HTMLInputElement).value = config.server;
    ($('#p-stls-port') as HTMLInputElement).value = config.server_port.toString();
    ($('#p-stls-version') as HTMLSelectElement).value = config.version.toString();
    ($('#p-stls-password') as HTMLInputElement).value = config.password;
    ($('#p-stls-sni') as HTMLInputElement).value = config.tls.server_name;
    alert(`Parsed: ${config.server}:${config.server_port} v${config.version}`);
  } catch (err) {
    alert('Failed to parse JSON: ' + err);
  }
}

// Proxy control
async function startProxy() {
  if (selectedProfileIndex === -1) return alert('Select a profile first');

  try {
    await invoke('start_proxy', { profileIndex: selectedProfileIndex });
    currentStatus = { state: 'Running', profile: currentConfig.profiles[selectedProfileIndex].name, local_port: currentConfig.profiles[selectedProfileIndex].local_socks_port };
    renderStatus(currentStatus);
    updateProxyButtons();
  } catch (err) {
    alert('Failed to start: ' + err);
    currentStatus = { state: 'Error', error: String(err) };
    renderStatus(currentStatus);
  }
}

async function stopProxy() {
  try {
    await invoke('stop_proxy');
    currentStatus = { state: 'Stopped' };
    renderStatus(currentStatus);
    updateProxyButtons();
  } catch (err) {
    alert('Failed to stop: ' + err);
  }
}

function updateProxyButtons() {
  const running = currentStatus.state === 'Running';
  ($('#btn-start') as HTMLButtonElement).disabled = running;
  ($('#btn-stop') as HTMLButtonElement).disabled = !running;
}

// Config persistence
async function loadConfig() {
  try {
    const config: AppConfig = await invoke('get_config');
    currentConfig = config;
    renderProfiles();
  } catch {
    currentConfig = { profiles: [], settings: { auto_start: false, minimize_to_tray: true, log_level: 'info' } };
  }
}

async function saveConfig() {
  await invoke('save_config', { config: currentConfig });
}

// Event listeners from backend
async function listenForEvents() {
  await listen('proxy-status', (event: any) => {
    currentStatus = event.payload;
    renderStatus(currentStatus);
    updateProxyButtons();
  });

  await listen('tray-start-proxy', () => {
    if (selectedProfileIndex !== -1) startProxy();
  });

  await listen('tray-stop-proxy', () => {
    stopProxy();
  });
}

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  initTabs();
  await loadConfig();
  await listenForEvents();

  // Modal events
  $('#add-profile-btn')?.addEventListener('click', () => openProfileModal());
  $('#profile-modal')?.addEventListener('close', closeProfileModal);
  $('#profile-form')?.addEventListener('submit', saveProfile);
  $('#cancel-profile')?.addEventListener('click', closeProfileModal);

  // Import/Export
  $('#export-btn')?.addEventListener('click', exportProfiles);
  $('#import-btn')?.addEventListener('change', importProfiles);

  // Parse buttons
  $('#parse-ss-btn')?.addEventListener('click', parseSsUri);
  $('#parse-stls-btn')?.addEventListener('click', parseStlsJson);

  // Proxy buttons
  $('#btn-start')?.addEventListener('click', startProxy);
  $('#btn-stop')?.addEventListener('click', stopProxy);

  // Initial render
  renderProfiles();
  renderStatus(currentStatus);
  updateProxyButtons();

  // Populate cipher select
  const cipherSelect = $('#p-cipher') as HTMLSelectElement;
  CIPHERS.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c;
    opt.textContent = c;
    cipherSelect.appendChild(opt);
  });
});

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Expose to global for onclick handlers
(window as any).editProfile = editProfile;
(window as any).deleteProfile = deleteProfile;
(window as any).testProfile = testProfile;