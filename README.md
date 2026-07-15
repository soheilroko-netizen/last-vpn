# stls

User-friendly ShadowTLS client for Windows. Combines Shadowsocks + ShadowTLS into a single system tray application.

## Features

- **Simple UI** - Paste your Shadowsocks URI and ShadowTLS JSON, or enter fields manually
- **System tray** - Connect/disconnect/status from tray icon
- **Profile management** - Add, edit, delete, import/export profiles (JSON)
- **SOCKS5 proxy** - Runs on `127.0.0.1:1080` (configurable)
- **Shadowsocks 2022** - Supports `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`
- **ShadowTLS V3** - Fake HTTP/TLS, SNI support, better detection resistance
- **Portable** - No installer needed, config in `%APPDATA%`
- **Cross-compiled** - Built via GitHub Actions on Windows runners

## Architecture

```
App (SOCKS5 1080) → Shadowsocks Local (1081) → ShadowTLS Client → Remote Server
```

Chain: Your app connects to `127.0.0.1:1080` → Shadowsocks encrypts → forwards to local ShadowTLS on `1081` → ShadowTLS wraps in fake HTTPS → remote ShadowTLS server → Shadowsocks server.

## Build

```bash
# Windows (MSVC)
cargo build --release --target x86_64-pc-windows-msvc

# Windows (GNU)
cargo build --release --target x86_64-pc-windows-gnu
```

Or push a tag to trigger GitHub Actions:
```bash
git tag v0.1.0 && git push origin v0.1.0
```

Artifacts: `.exe` (portable) and `.msi` (installer) in Actions → Artifacts or Releases.

## Configuration

Config stored at `%APPDATA%\stls\config.json`:

```json
{
  "profiles": [
    {
      "name": "My Server",
      "shadowsocks": {
        "cipher": "2022-blake3-chacha20-poly1305",
        "password": "base64password==",
        "server": "auto",
        "port": 0
      },
      "shadowtls": {
        "server": "example.com",
        "server_port": 443,
        "version": 3,
        "password": "shadowtls-password",
        "tls": {
          "enabled": true,
          "server_name": "dl.google.com",
          "insecure": false
        }
      },
      "local_socks_port": 1080
    }
  ],
  "settings": {
    "auto_start": false,
    "minimize_to_tray": true,
    "log_level": "info"
  }
}
```

## Input Formats

### Shadowsocks URI (SIP002)
```
ss://2022-blake3-chacha20-poly1305:password@server:port#name
```

### ShadowTLS JSON (sing-box/Xray style)
```json
{
  "type": "shadowtls",
  "server": "example.com",
  "server_port": 443,
  "version": 3,
  "password": "password",
  "tls": {
    "enabled": true,
    "server_name": "dl.google.com"
  }
}
```

## Requirements

- Windows 10 1809+ (for WebView2)
- Visual C++ Redistributable (for MSVC build)

## License

MIT