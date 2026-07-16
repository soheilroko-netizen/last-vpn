# stls v5 - GUI Version

ShadowTLS + Shadowsocks proxy client with graphical interface.

## Features

- **GUI Interface** - Clean, modern desktop UI
- **Start/Stop Controls** - One-click proxy management
- **Connection Status** - Visual indicator (connected/disconnected)
- **Auto-download** - Automatically fetches latest sing-box binary
- **Windows Native** - Built with Tauri (Rust + Web frontend)

## What's New in v5

- Added graphical user interface
- System tray integration (planned for v5.1)
- Profile management UI (planned for v6)
- TUN/VPN mode (planned for v7)

## Download

Download the latest release from the [Releases](https://github.com/soheilroko-netizen/stls/releases) page:
- `stls_5.0.0_x64_en-US.msi` - Windows installer
- `stls_5.0.0_x64-setup.exe` - Portable executable

## Usage

1. Run `stls.exe`
2. Click **Start** to connect
3. Configure your apps to use SOCKS5 proxy: `127.0.0.1:1080`
4. Click **Stop** to disconnect

## Default Server

- Server: `ns.baft.uk:8553`
- SOCKS5: `127.0.0.1:1080`
- Protocol: ShadowTLS v3 + Shadowsocks 2022

## Build from Source

Requires: Rust, Node.js 22+, pnpm

```bash
git clone https://github.com/soheilroko-netizen/stls.git
cd stls
git checkout v5
pnpm install
pnpm tauri build
```

Binary will be in `src-tauri/target/release/bundle/`

## License

MIT
