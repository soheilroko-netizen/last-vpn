# stls v4 — minimal ShadowTLS + Shadowsocks chain proxy (CLI)

A tiny Rust command-line client that turns your nekoray config into a working
SOCKS5 proxy on **`127.0.0.1:1080`**.

It auto-downloads [`sing-box`](https://sing-box.sagernet.org/), writes the
chain config, and launches it. No installer, no GUI, no Node — just one `.exe`.

## What it does

```
Your app → SOCKS5 127.0.0.1:1080
                → ShadowTLS v3  (ns.baft.uk:8553, fake TLS to dl.google.com)
                    → Shadowsocks 2022 (ns.baft.uk:8380, blake3-chacha20-poly1305)
```

This is the exact chain from your nekoray export:

| Layer | Server | Port | Password | Notes |
|-------|--------|------|----------|-------|
| ShadowTLS v3 | `ns.baft.uk` | `8553` | `y2lachetore` | SNI `dl.google.com` |
| Shadowsocks 2022 | `ns.baft.uk` | `8380` | `tE+3/qlN/orCZRVUutWouysZ8BQs4RWzq46WK6CDGG4=` | `2022-blake3-chacha20-poly1305` |
| Local SOCKS5 | `127.0.0.1` | `1080` | — | listen address |

## Usage

1. Download `stls.exe` from **Actions → Artifacts** (or a tagged Release).
2. Run it. On first launch it downloads `sing-box.exe` next to it
   (into `%APPDATA%\stls\`).
3. Point your browser / game / app at SOCKS5 `127.0.0.1:1080`.
4. Press `Ctrl+C` to stop.

> Needs outbound HTTPS to `github.com` (first run, to fetch sing-box) and to
> `ns.baft.uk` (the proxy itself).

## Build from source (Windows, MSVC)

```bash
cargo build --release --target x86_64-pc-windows-msvc
# result: target\x86_64-pc-windows-msvc\release\stls.exe
```

Or push a tag to trigger GitHub Actions:

```bash
git tag v4.0.0 && git push origin v4.0.0
```

## Edit the config

You don't need to rebuild to change servers/ports. Two ways:

**1. `profile.toml` (no rebuild, recommended)**

Copy `profile.toml.example` to `profile.toml` next to `stls.exe`, edit the
values you want, and re-run. Every field is optional — anything you omit falls
back to the built-in defaults.

```bash
# dump the current effective profile to profile.toml so you can see the format:
stls.exe --write-profile
```

**2. Command-line**

```bash
stls.exe --profile C:\path\to\profile.toml   # load a specific file
stls.exe --help                               # show usage + field names
```

**3. Build-time defaults**

To bake different defaults in, edit `Profile::default()` in `src/main.rs` and
rebuild (or push a tag to trigger GitHub Actions).

## License

MIT
