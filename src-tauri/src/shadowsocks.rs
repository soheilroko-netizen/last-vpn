// Shadowsocks Local Server & Client Implementation
// Supports 2022 AEAD ciphers (blake3-aes-128-gcm, blake3-aes-256-gcm, blake3-chacha20-poly1305)

use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use aes_gcm::aead::Aead;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::{debug, error, info, warn};

use crate::config::ShadowsocksConfig;
use crate::crypto::{decode_ss_uri, encode_ss_uri, hmac_sha1, kdf, random_bytes, verify_hmac,
    FAKE_HTTP_HEADER, FAKE_REQUEST_LENGTH_RANGE, TLS_APPLICATION_DATA, TLS_HANDSHAKE,
    TLS_HMAC_SIZE, TLS_RANDOM_SIZE, TLS_SESSION_ID_SIZE, TLS_SERVER_HELLO, TLS_VERSION_1_2,
};

mod socks5 {
    use super::*;

    pub const VERSION: u8 = 0x05;
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;
    pub const AUTH_NONE: u8 = 0x00;
    pub const AUTH_GSSAPI: u8 = 0x01;
    pub const AUTH_USERPASS: u8 = 0x02;
    pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

    pub const REP_SUCCESS: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const REP_HOST_UNREACHABLE: u8 = 0x04;
    pub const REP_CONNECTION_REFUSED: u8 = 0x05;
    pub const REP_TTL_EXPIRED: u8 = 0x06;
    pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

    pub async fn handle_handshake(stream: &mut TcpStream) -> Result<()> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf[0] != VERSION {
            bail!("Unsupported SOCKS version: {}", buf[0]);
        }
        let nmethods = buf[1] as usize;

        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        let response = [VERSION, AUTH_NONE];
        stream.write_all(&response).await?;
        Ok(())
    }

    pub async fn handle_request(stream: &mut TcpStream) -> Result<(SocketAddr, SocketAddr)> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        
        if buf[0] != VERSION {
            bail!("Invalid SOCKS version in request");
        }
        if buf[1] != CMD_CONNECT {
            bail!("Unsupported command: {}", buf[1]);
        }
        let atyp = buf[3];

        let (addr, bind_addr) = match atyp {
            ATYP_IPV4 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                let addr = SocketAddr::from((ip, port));
                (addr, addr)
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain)?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", domain, port))
                    .await?
                    .collect();
                let addr = addrs.first().copied()
                    .ok_or_else(|| anyhow::anyhow!("Failed to resolve domain"))?;
                let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));
                (addr, bind_addr)
            }
            ATYP_IPV6 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port = u16::from_be_bytes(port);
                let addr = SocketAddr::from((ip, port));
                (addr, addr)
            }
            _ => bail!("Unsupported address type: {}", atyp),
        };

        Ok((addr, bind_addr))
    }

    pub async fn send_response(stream: &mut TcpStream, rep: u8, bind_addr: &SocketAddr) -> Result<()> {
        let mut response = Vec::with_capacity(10);
        response.push(VERSION);
        response.push(rep);
        response.push(0); // reserved
        
        match bind_addr {
            SocketAddr::V4(v4) => {
                response.push(ATYP_IPV4);
                response.extend_from_slice(&v4.ip().octets());
                response.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                response.push(ATYP_IPV6);
                response.extend_from_slice(&v6.ip().octets());
                response.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        
        stream.write_all(&response).await?;
        Ok(())
    }
}

/// AEAD Cipher for Shadowsocks 2022
mod cipher2022 {
    use super::*;
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce};
    use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
    use blake3;
    use sha2::Sha256;
    use zeroize::Zeroize;

    pub trait AeadCipher: Send + Sync {
        fn encrypt(&mut self, nonce: &[u8], plaintext: &[u8], out: &mut Vec<u8>) -> Result<()>;
        fn decrypt(&mut self, nonce: &[u8], ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()>;
        fn key_len(&self) -> usize;
        fn nonce_len(&self) -> usize;
        fn tag_len(&self) -> usize;
        fn boxed_clone(&self) -> Box<dyn AeadCipher>;
    }

    pub struct Aes128GcmCipher {
        cipher: Aes128Gcm,
        key: [u8; 16],
    }

    impl Aes128GcmCipher {
        pub fn new(key: &[u8]) -> Result<Self> {
            if key.len() != 16 {
                bail!("AES-128-GCM key must be 16 bytes");
            }
            let mut k = [0u8; 16];
            k.copy_from_slice(key);
            let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
            Ok(Self { cipher, key: k })
        }
    }

    impl AeadCipher for Aes128GcmCipher {
        fn encrypt(&mut self, nonce: &[u8], plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
            let nonce = Nonce::from_slice(nonce);
            let ct = self.cipher.encrypt(nonce, plaintext)
                .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            out.extend_from_slice(&ct);
            Ok(())
        }

        fn decrypt(&mut self, nonce: &[u8], ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
            let nonce = Nonce::from_slice(nonce);
            let pt = self.cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
            out.extend_from_slice(&pt);
            Ok(())
        }

        fn key_len(&self) -> usize { 16 }
        fn nonce_len(&self) -> usize { 12 }
        fn tag_len(&self) -> usize { 16 }
        
        fn boxed_clone(&self) -> Box<dyn AeadCipher> {
            let mut k = [0u8; 16];
            k.copy_from_slice(&self.key);
            Box::new(Aes128GcmCipher::new(&k).unwrap())
        }
    }

    pub struct Aes256GcmCipher {
        cipher: Aes256Gcm,
        key: [u8; 32],
    }

    impl Aes256GcmCipher {
        pub fn new(key: &[u8]) -> Result<Self> {
            if key.len() != 32 {
                bail!("AES-256-GCM key must be 32 bytes");
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(key);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k));
            Ok(Self { cipher, key: k })
        }
    }

    impl AeadCipher for Aes256GcmCipher {
        fn encrypt(&mut self, nonce: &[u8], plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
            let nonce = Nonce::from_slice(nonce);
            let ct = self.cipher.encrypt(nonce, plaintext)
                .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            out.extend_from_slice(&ct);
            Ok(())
        }

        fn decrypt(&mut self, nonce: &[u8], ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
            let nonce = Nonce::from_slice(nonce);
            let pt = self.cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
            out.extend_from_slice(&pt);
            Ok(())
        }

        fn key_len(&self) -> usize { 32 }
        fn nonce_len(&self) -> usize { 12 }
        fn tag_len(&self) -> usize { 16 }
        
        fn boxed_clone(&self) -> Box<dyn AeadCipher> {
            let mut k = [0u8; 32];
            k.copy_from_slice(&self.key);
            Box::new(Aes256GcmCipher::new(&k).unwrap())
        }
    }

    pub struct ChaCha20Poly1305Cipher {
        cipher: ChaCha20Poly1305,
        key: [u8; 32],
    }

    impl ChaCha20Poly1305Cipher {
        pub fn new(key: &[u8]) -> Result<Self> {
            if key.len() != 32 {
                bail!("ChaCha20-Poly1305 key must be 32 bytes");
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(key);
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&k));
            Ok(Self { cipher, key: k })
        }
    }

    impl AeadCipher for ChaCha20Poly1305Cipher {
        fn encrypt(&mut self, nonce: &[u8], plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
            let nonce = ChaChaNonce::from_slice(nonce);
            let ct = self.cipher.encrypt(nonce, plaintext)
                .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            out.extend_from_slice(&ct);
            Ok(())
        }

        fn decrypt(&mut self, nonce: &[u8], ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
            let nonce = ChaChaNonce::from_slice(nonce);
            let pt = self.cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
            out.extend_from_slice(&pt);
            Ok(())
        }

        fn key_len(&self) -> usize { 32 }
        fn nonce_len(&self) -> usize { 12 }
        fn tag_len(&self) -> usize { 16 }
        
        fn boxed_clone(&self) -> Box<dyn AeadCipher> {
            let mut k = [0u8; 32];
            k.copy_from_slice(&self.key);
            Box::new(ChaCha20Poly1305Cipher::new(&k).unwrap())
        }
    }

    /// 2022-blake3-aes-128-gcm
    pub fn create_blake3_aes128_gcm(password: &str) -> Result<Box<dyn AeadCipher>> {
        let key = derive_key_blake3(password, 16)?;
        Ok(Box::new(Aes128GcmCipher::new(&key)?))
    }

    /// 2022-blake3-aes-256-gcm
    pub fn create_blake3_aes256_gcm(password: &str) -> Result<Box<dyn AeadCipher>> {
        let key = derive_key_blake3(password, 32)?;
        Ok(Box::new(Aes256GcmCipher::new(&key)?))
    }

    /// 2022-blake3-chacha20-poly1305
    pub fn create_blake3_chacha20_poly1305(password: &str) -> Result<Box<dyn AeadCipher>> {
        let key = derive_key_blake3(password, 32)?;
        Ok(Box::new(ChaCha20Poly1305Cipher::new(&key)?))
    }

    fn derive_key_blake3(password: &str, key_len: usize) -> Result<Vec<u8>> {
        // shadowsocks-rust 2022 derives the PSK via blake3::derive_key (32-byte output),
        // then truncates for shorter ciphers.
        let full = blake3::derive_key("shadowsocks 2022", password.as_bytes());
        Ok(full[..key_len].to_vec())
    }

    /// Legacy ciphers
    pub fn create_cipher(method: &str, password: &str) -> Result<Box<dyn AeadCipher>> {
        match method {
            "2022-blake3-aes-128-gcm" => create_blake3_aes128_gcm(password),
            "2022-blake3-aes-256-gcm" => create_blake3_aes256_gcm(password),
            "2022-blake3-chacha20-poly1305" => create_blake3_chacha20_poly1305(password),
            "aes-256-gcm" => {
                let key = derive_key_legacy(password, 32)?;
                Ok(Box::new(Aes256GcmCipher::new(&key)?))
            }
            "aes-128-gcm" => {
                let key = derive_key_legacy(password, 16)?;
                Ok(Box::new(Aes128GcmCipher::new(&key)?))
            }
            "chacha20-ietf-poly1305" => {
                let key = derive_key_legacy(password, 32)?;
                Ok(Box::new(ChaCha20Poly1305Cipher::new(&key)?))
            }
            _ => bail!("Unsupported cipher: {}", method),
        }
    }

    fn derive_key_legacy(password: &str, key_len: usize) -> Result<Vec<u8>> {
        let mut key = vec![0u8; key_len];
        let mut md5 = md5::Context::new();
        md5.consume(password.as_bytes());
        let hash = md5.compute();
        key[..16].copy_from_slice(hash.as_ref());
        
        if key_len > 16 {
            let mut md5 = md5::Context::new();
            md5.consume(hash.as_ref());
            md5.consume(password.as_bytes());
            let hash2 = md5.compute();
            key[16..].copy_from_slice(&hash2.as_ref()[..key_len - 16]);
        }
        
        Ok(key)
    }
}

use cipher2022::{AeadCipher, create_cipher};

/// Shadowsocks 2022 TCP Stream
pub struct SsStream {
    socket: TcpStream,
    cipher: Box<dyn AeadCipher>,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    recv_nonce: [u8; 12],
    send_nonce: [u8; 12],
    chunk_size: usize,
}

impl SsStream {
    pub fn new(socket: TcpStream, cipher: Box<dyn AeadCipher>) -> Self {
        Self {
            socket,
            cipher,
            read_buffer: BytesMut::with_capacity(16384),
            write_buffer: BytesMut::with_capacity(16384),
            recv_nonce: [0u8; 12],
            send_nonce: [0u8; 12],
            chunk_size: 16384,
        }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            if self.read_buffer.len() >= 2 {
                let payload_len = u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;
                let total_len = 2 + payload_len + self.cipher.tag_len();
                
                if self.read_buffer.len() >= total_len {
                    let mut decrypted = Vec::new();
                    let nonce = self.recv_nonce;
                    self.cipher.decrypt(&nonce, &self.read_buffer[2..total_len], &mut decrypted)?;
                    Self::increment_nonce(&mut self.recv_nonce);

                    self.read_buffer.advance(total_len);
                    
                    let n = decrypted.len().min(buf.len());
                    buf[..n].copy_from_slice(&decrypted[..n]);
                    return Ok(n);
                }
            }
            
            let n = self.socket.read_buf(&mut self.read_buffer).await?;
            if n == 0 {
                return Ok(0);
            }
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let chunk_end = (written + self.chunk_size).min(buf.len());
            let chunk = &buf[written..chunk_end];
            
            let mut encrypted = Vec::new();
            let nonce = self.send_nonce;
            Self::increment_nonce(&mut self.send_nonce);
            
            self.cipher.encrypt(&nonce, chunk, &mut encrypted)?;
            
            self.write_buffer.clear();
            self.write_buffer.put_u16(encrypted.len() as u16);
            self.write_buffer.extend_from_slice(&encrypted);
            
            self.socket.write_all(&self.write_buffer).await?;
            written = chunk_end;
        }
        
        Ok(written)
    }

    fn increment_nonce(nonce: &mut [u8; 12]) {
        for i in (4..12).rev() {
            nonce[i] = nonce[i].wrapping_add(1);
            if nonce[i] != 0 {
                break;
            }
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.socket.flush().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.socket.shutdown().await?;
        Ok(())
    }
}

/// Shadowsocks Local Server
pub struct ShadowsocksLocal {
    config: ShadowsocksConfig,
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    cipher: Arc<Mutex<Box<dyn AeadCipher>>>,
}

impl ShadowsocksLocal {
    pub async fn new(config: ShadowsocksConfig, listen_port: u16, upstream_port: u16) -> Result<Self> {
        let listen_addr = SocketAddr::from(([127, 0, 0, 1], listen_port));
        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        
        let cipher = create_cipher(&config.cipher, &config.password)?;
        
        Ok(Self {
            config,
            listen_addr,
            upstream_addr,
            cipher: Arc::new(Mutex::new(cipher)),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("Shadowsocks SOCKS5 server listening on {}", self.listen_addr);

        let upstream = self.upstream_addr;
        let cipher = self.cipher.clone();

        loop {
            let (client, addr) = listener.accept().await?;
            debug!("SOCKS5 connection from {}", addr);
            
            let upstream = upstream;
            let cipher = cipher.clone();
            
            tokio::spawn(async move {
                if let Err(e) = handle_connection(client, upstream, cipher).await {
                    debug!("Connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    upstream_addr: SocketAddr,
    cipher: Arc<Mutex<Box<dyn AeadCipher>>>,
) -> Result<()> {
    socks5::handle_handshake(&mut client).await?;
    
    let (_target_addr, bind_addr) = socks5::handle_request(&mut client).await?;
    
    let mut upstream = TcpStream::connect(upstream_addr).await?;
    
    socks5::send_response(&mut client, socks5::REP_SUCCESS, &bind_addr).await?;
    
    let mut client_encrypted = SsStream::new(client, cipher.lock().await.boxed_clone());
    let mut upstream_encrypted = SsStream::new(upstream, cipher.lock().await.boxed_clone());

    let mut client_buf = [0u8; 16384];
    let mut upstream_buf = [0u8; 16384];
    loop {
        tokio::select! {
            n = client_encrypted.read(&mut client_buf) => {
                let n = n?;
                if n == 0 { break; }
                upstream_encrypted.write(&client_buf[..n]).await?;
            }
            n = upstream_encrypted.read(&mut upstream_buf) => {
                let n = n?;
                if n == 0 { break; }
                client_encrypted.write(&upstream_buf[..n]).await?;
            }
        }
    }
    let _ = client_encrypted.shutdown().await;
    let _ = upstream_encrypted.shutdown().await;

    Ok(())
}

pub struct ShadowsocksClient;

impl ShadowsocksClient {
    pub async fn test_connection(local_port: u16) -> Result<()> {
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], local_port));
        let mut stream = TcpStream::connect(proxy_addr).await?;
        
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            bail!("SOCKS5 handshake failed");
        }
        
        let target = "www.google.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03];
        req.push(target.len() as u8);
        req.extend_from_slice(target.as_bytes());
        req.extend_from_slice(&80u16.to_be_bytes());
        
        stream.write_all(&req).await?;
        let mut resp = [0u8; 10];
        stream.read_exact(&mut resp).await?;
        
        if resp[1] != 0x00 {
            bail!("SOCKS5 connect failed: {}", resp[1]);
        }
        
        stream.write_all(b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n").await?;
        
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await?;
        
        if n == 0 {
            bail!("No response from test endpoint");
        }
        
        Ok(())
    }
}

/// SIP002 URI parsing
pub fn parse_ss_uri(uri: &str) -> Result<ShadowsocksConfig> {
    let (method, password, server, port) = decode_ss_uri(uri)?;
    
    Ok(ShadowsocksConfig {
        cipher: method,
        password,
        server,
        port,
        plugin: None,
        plugin_opts: None,
    })
}

pub fn generate_ss_uri(config: &ShadowsocksConfig) -> String {
    encode_ss_uri(&config.cipher, &config.password, &config.server, config.port, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_uri() {
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#Test";
        let config = parse_ss_uri(uri).unwrap();
        assert_eq!(config.cipher, "aes-256-gcm");
        assert_eq!(config.password, "password");
        assert_eq!(config.server, "1.2.3.4");
        assert_eq!(config.port, 8388);
    }

    #[test]
    fn test_generate_ss_uri() {
        let config = ShadowsocksConfig {
            cipher: "aes-256-gcm".to_string(),
            password: "password".to_string(),
            server: "1.2.3.4".to_string(),
            port: 8388,
            plugin: None,
            plugin_opts: None,
        };
        let uri = generate_ss_uri(&config);
        assert!(uri.starts_with("ss://"));
    }
}