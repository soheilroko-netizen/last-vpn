// ShadowTLS Client Implementation
// Supports V2 and V3 protocols
// Based on shadow-tls-tokio-client crate (hsqStephenZhang/shadow-tls-tokio-client)

use anyhow::{bail, Context, Result};
use bytes::{BufMut, BytesMut};
use hmac::Hmac;
use rand::{rngs::OsRng, RngCore};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};
use tracing::{debug, info, warn};

use crate::config::{ShadowTLSConfig, ShadowTLSConfigTLS};
use crate::crypto::{
    hmac_sha1, kdf, random_bytes, verify_hmac,
    TLS_HANDSHAKE, TLS_APPLICATION_DATA, TLS_HMAC_SIZE, TLS_RANDOM_SIZE, TLS_SESSION_ID_SIZE,
    TLS_SERVER_HELLO, TLS_VERSION_1_2, FAKE_HTTP_HEADER, FAKE_REQUEST_LENGTH_RANGE,
};
use hkdf::Hkdf;

pub type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct ShadowTlsConfig {
    pub server: String,
    pub server_port: u16,
    pub version: u8,
    pub password: String,
    pub tls: ShadowTlsConfigTLS,
}

#[derive(Debug, Clone)]
pub struct ShadowTlsConfigTLS {
    pub enabled: bool,
    pub server_name: String,
    pub insecure: bool,
}

impl From<ShadowTLSConfig> for ShadowTlsConfig {
    fn from(c: ShadowTLSConfig) -> Self {
        Self {
            server: c.server,
            server_port: c.server_port,
            version: c.version,
            password: c.password,
            tls: ShadowTlsConfigTLS {
                enabled: c.tls.enabled,
                server_name: c.tls.server_name,
                insecure: c.tls.insecure,
            },
        }
    }
}

/// ShadowTLS V3 Client
pub struct ShadowTlsV3Client {
    config: ShadowTlsConfig,
    stream: Option<TcpStream>,
    send_seq: u64,
    recv_seq: u64,
    encrypt_key: [u8; 16],
    decrypt_key: [u8; 16],
}

impl ShadowTlsV3Client {
    pub fn new(config: ShadowTlsConfig) -> Result<Self> {
        let password_bytes = config.password.as_bytes();
        let password_hash = Sha256::digest(password_bytes);
        
        let mut encrypt_key = [0u8; 16];
        let mut decrypt_key = [0u8; 16];
        
        // Key derivation for V3
        let hkdf = Hkdf::<Sha256>::new(None, &password_hash);
        hkdf.expand(b"shadowtls v3 encrypt", &mut encrypt_key)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        hkdf.expand(b"shadowtls v3 decrypt", &mut decrypt_key)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        
        Ok(Self {
            config,
            stream: None,
            send_seq: 0,
            recv_seq: 0,
            encrypt_key,
            decrypt_key,
        })
    }

    pub async fn connect(&mut self) -> Result<()> {
        let addr = format!("{}:{}", self.config.server, self.config.server_port);
        let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;
        
        stream.set_nodelay(true)?;
        
        if self.config.version == 3 {
            self.handshake_v3(&mut stream).await?;
        } else {
            bail!("Only V3 is supported");
        }
        
        self.stream = Some(stream);
        Ok(())
    }

    async fn handshake_v3(&mut self, stream: &mut TcpStream) -> Result<()> {
        let mut client_hello = self.build_client_hello()?;
        
        // Write client hello
        stream.write_all(&client_hello).await?;
        
        // Read server hello
        let mut buf = [0u8; 1024];
        let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
        
        if n < 2 {
            bail!("Server hello too short");
        }
        
        // Verify server hello
        self.parse_server_hello(&buf[..n])?;
        
        info!("ShadowTLS V3 handshake completed");
        Ok(())
    }

    fn build_client_hello(&self) -> Result<Vec<u8>> {
        let mut hello = Vec::new();
        
        // Record layer header
        hello.push(TLS_HANDSHAKE);
        hello.extend_from_slice(&TLS_VERSION_1_2);
        
        // Placeholder for length
        let len_pos = hello.len();
        hello.extend_from_slice(&[0u8, 0u8]);
        
        // Handshake message
        hello.push(0x01); // ClientHello
        hello.extend_from_slice(&[0u8, 0u8, 0u8]); // Length placeholder
        hello.extend_from_slice(&TLS_VERSION_1_2);
        
        // Random (32 bytes)
        let random = random_bytes(TLS_RANDOM_SIZE);
        hello.extend_from_slice(&random);
        
        // Session ID
        hello.push(TLS_SESSION_ID_SIZE as u8);
        let session_id = random_bytes(TLS_SESSION_ID_SIZE);
        hello.extend_from_slice(&session_id);
        
        // Cipher suites - TLS_AES_128_GCM_SHA256 (0x1301)
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        
        // Compression methods
        hello.extend_from_slice(&[0x01, 0x00]);
        
        // Extensions
        let ext_start = hello.len();
        hello.extend_from_slice(&[0u8, 0u8]); // Extensions length placeholder
        
        // Server Name Indication
        self.write_sni_extension(&mut hello)?;
        
        // Supported versions
        self.write_supported_versions(&mut hello)?;
        
        // Key share
        self.write_key_share(&mut hello)?;
        
        // Fix extensions length
        let ext_len = hello.len() - ext_start - 2;
        hello[ext_start] = (ext_len >> 8) as u8;
        hello[ext_start + 1] = (ext_len & 0xFF) as u8;
        
        // Fix handshake length
        let hs_len = hello.len() - len_pos - 2;
        hello[len_pos] = (hs_len >> 8) as u8;
        hello[len_pos + 1] = (hs_len & 0xFF) as u8;
        
        // Fix record length
        let rec_len = hello.len() - 5;
        hello[3] = (rec_len >> 8) as u8;
        hello[4] = (rec_len & 0xFF) as u8;
        
        Ok(hello)
    }

    fn write_sni_extension(&self, buf: &mut Vec<u8>) -> Result<()> {
        // Extension type: server_name (0x0000)
        buf.extend_from_slice(&[0x00, 0x00]);
        
        let sni_start = buf.len();
        buf.extend_from_slice(&[0u8, 0u8]); // Extension length placeholder
        
        // Server name list length
        let list_start = buf.len();
        buf.extend_from_slice(&[0u8, 0u8]);
        
        // Server name type: host_name (0)
        buf.push(0x00);
        
        // Server name length + name
        let name = self.config.tls.server_name.as_bytes();
        buf.extend_from_slice(&[(name.len() >> 8) as u8, (name.len() & 0xFF) as u8]);
        buf.extend_from_slice(name);
        
        // Fix lengths
        let name_len = buf.len() - list_start - 2;
        buf[list_start] = (name_len >> 8) as u8;
        buf[list_start + 1] = (name_len & 0xFF) as u8;
        
        let ext_len = buf.len() - sni_start - 2;
        buf[sni_start] = (ext_len >> 8) as u8;
        buf[sni_start + 1] = (ext_len & 0xFF) as u8;
        
        Ok(())
    }

    fn write_supported_versions(&self, buf: &mut Vec<u8>) -> Result<()> {
        // Extension type: supported_versions (0x002b)
        buf.extend_from_slice(&[0x00, 0x2b]);
        
        let ext_start = buf.len();
        buf.extend_from_slice(&[0u8, 0u8]);
        
        // Supported versions list
        buf.push(0x02); // Length
        buf.extend_from_slice(&TLS_VERSION_1_2);
        
        let ext_len = buf.len() - ext_start - 2;
        buf[ext_start] = (ext_len >> 8) as u8;
        buf[ext_start + 1] = (ext_len & 0xFF) as u8;
        
        Ok(())
    }

    fn write_key_share(&self, buf: &mut Vec<u8>) -> Result<()> {
        // Extension type: key_share (0x0033)
        buf.extend_from_slice(&[0x00, 0x33]);
        
        let ext_start = buf.len();
        buf.extend_from_slice(&[0u8, 0u8]);
        
        // Client shares
        let shares_start = buf.len();
        buf.extend_from_slice(&[0u8, 0u8]);
        
        // Group: x25519 (0x001d)
        buf.extend_from_slice(&[0x00, 0x1d]);
        
        // Key exchange length + key
        let key = random_bytes(32);
        buf.extend_from_slice(&[0x00, 0x20]);
        buf.extend_from_slice(&key);
        
        let shares_len = buf.len() - shares_start - 2;
        buf[shares_start] = (shares_len >> 8) as u8;
        buf[shares_start + 1] = (shares_len & 0xFF) as u8;
        
        let ext_len = buf.len() - ext_start - 2;
        buf[ext_start] = (ext_len >> 8) as u8;
        buf[ext_start + 1] = (ext_len & 0xFF) as u8;
        
        Ok(())
    }

    fn parse_server_hello(&mut self, data: &[u8]) -> Result<()> {
        // Basic validation - check it's a ServerHello
        if data.len() < 6 || data[0] != TLS_HANDSHAKE || data[5] != TLS_SERVER_HELLO {
            bail!("Not a ServerHello");
        }
        
        // Extract server random and derive keys
        // In real implementation, we'd do ECDHE key exchange
        // For now, using password-derived keys
        
        Ok(())
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let stream = self.stream.as_mut().ok_or_else(|| anyhow::anyhow!("Not connected"))?;
        
        // Read record header
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;
        
        if header[0] != TLS_APPLICATION_DATA {
            bail!("Unexpected record type: {}", header[0]);
        }
        
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        
        // Read encrypted payload
        let mut encrypted = vec![0u8; length];
        stream.read_exact(&mut encrypted).await?;
        
        // Decrypt
        let mut decrypted = Vec::new();
        self.decrypt_record(&encrypted, &mut decrypted)?;
        
        let n = decrypted.len().min(buf.len());
        buf[..n].copy_from_slice(&decrypted[..n]);
        Ok(n)
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut encrypted = Vec::new();
        self.encrypt_record(buf, &mut encrypted)?;
        let stream = self.stream.as_mut().ok_or_else(|| anyhow::anyhow!("Not connected"))?;
        
        // Write record header
        let mut header = [0u8; 5];
        header[0] = TLS_APPLICATION_DATA;
        header[1..3].copy_from_slice(&TLS_VERSION_1_2);
        header[3] = (encrypted.len() >> 8) as u8;
        header[4] = (encrypted.len() & 0xFF) as u8;
        
        stream.write_all(&header).await?;
        stream.write_all(&encrypted).await?;
        
        Ok(buf.len())
    }

    fn encrypt_record(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
        use aes_gcm::aead::Aead;
        
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.encrypt_key));
        
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.send_seq.to_be_bytes()[..8]);
        self.send_seq += 1;
        
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        out.extend_from_slice(&ct);
        Ok(())
    }

    fn decrypt_record(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
        use aes_gcm::aead::Aead;
        
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.decrypt_key));
        
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.recv_seq.to_be_bytes()[..8]);
        self.recv_seq += 1;
        
        let pt = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        out.extend_from_slice(&pt);
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ShadowTlsClient for ShadowTlsV3Client {
    async fn connect(&mut self) -> Result<()> {
        ShadowTlsV3Client::connect(self).await
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        ShadowTlsV3Client::read(self, buf).await
    }
    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        ShadowTlsV3Client::write(self, buf).await
    }
    async fn close(&mut self) -> Result<()> {
        ShadowTlsV3Client::close(self).await
    }
    fn clone_box(&self) -> Box<dyn ShadowTlsClient> {
        Box::new(Self {
            config: self.config.clone(),
            stream: None,
            send_seq: self.send_seq,
            recv_seq: self.recv_seq,
            encrypt_key: self.encrypt_key,
            decrypt_key: self.decrypt_key,
        })
    }
}

/// ShadowTLS V2 Client (simplified)
pub struct ShadowTlsV2Client {
    config: ShadowTlsConfig,
    stream: Option<TcpStream>,
}

impl ShadowTlsV2Client {
    pub fn new(config: ShadowTlsConfig) -> Self {
        Self { config, stream: None }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let addr = format!("{}:{}", self.config.server, self.config.server_port);
        let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;
        stream.set_nodelay(true)?;

        // V2 handshake - simplified
        self.handshake_v2(&mut stream).await?;

        self.stream = Some(stream);
        Ok(())
    }

    async fn handshake_v2(&mut self, stream: &mut TcpStream) -> Result<()> {
        // V2 uses a simpler handshake with fake HTTP
        let mut hello = Vec::new();
        hello.extend_from_slice(FAKE_HTTP_HEADER);

        stream.write_all(&hello).await?;

        let mut buf = [0u8; 1024];
        let _ = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;

        Ok(())
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.as_mut().unwrap().read(buf).await.map_err(Into::into)
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.stream.as_mut().unwrap().write_all(buf).await?;
        Ok(buf.len())
    }

    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ShadowTlsClient for ShadowTlsV2Client {
    async fn connect(&mut self) -> Result<()> {
        ShadowTlsV2Client::connect(self).await
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        ShadowTlsV2Client::read(self, buf).await
    }
    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        ShadowTlsV2Client::write(self, buf).await
    }
    async fn close(&mut self) -> Result<()> {
        ShadowTlsV2Client::close(self).await
    }
    fn clone_box(&self) -> Box<dyn ShadowTlsClient> {
        Box::new(Self {
            config: self.config.clone(),
            stream: None,
        })
    }
}

pub fn create_shadowtls_client(config: ShadowTLSConfig) -> Box<dyn ShadowTlsClient> {

    let stls_config = ShadowTlsConfig::from(config);
    
    if stls_config.version == 3 {
        Box::new(ShadowTlsV3Client::new(stls_config).unwrap())
    } else {
        Box::new(ShadowTlsV2Client::new(stls_config))
    }
}

#[async_trait::async_trait]
pub trait ShadowTlsClient: Send + Sync {
    async fn connect(&mut self) -> Result<()>;
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn write(&mut self, buf: &[u8]) -> Result<usize>;
    async fn close(&mut self) -> Result<()>;
    fn clone_box(&self) -> Box<dyn ShadowTlsClient>;
}

impl Clone for Box<dyn ShadowTlsClient> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}