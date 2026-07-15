use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha1::Sha1;
use sha2::Sha256;
use std::str::FromStr;

pub type HmacSha1 = Hmac<Sha1>;

pub const TLS_HANDSHAKE: u8 = 0x16;
pub const TLS_APPLICATION_DATA: u8 = 0x17;
pub const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];
pub const TLS_RANDOM_SIZE: usize = 32;
pub const TLS_SESSION_ID_SIZE: usize = 32;
pub const TLS_HMAC_SIZE: usize = 10;
pub const TLS_SERVER_HELLO: u8 = 0x0B;
pub const FAKE_HTTP_HEADER: &[u8] = b"GET / HTTP/1.1\r\nHost: dl.google.com\r\nConnection: keep-alive\r\n\r\n";
pub const FAKE_REQUEST_LENGTH_RANGE: std::ops::Range<usize> = 100..200;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8]) -> Result<()> {
    let computed = hmac_sha1(key, data);
    if computed[..expected.len()] == *expected {
        Ok(())
    } else {
        Err(anyhow::anyhow!("HMAC verification failed"))
    }
}

pub fn kdf(password: &str, salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut out = vec![0u8; out_len];
    hkdf.expand(info, &mut out).unwrap();
    out
}

pub fn decode_ss_uri(uri: &str) -> Result<(String, String, String, u16)> {
    if !uri.starts_with("ss://") {
        return Err(anyhow::anyhow!("Invalid Shadowsocks URI"));
    }
    
    let uri = &uri[5..];
    let (main_part, _name) = if let Some(idx) = uri.find('#') {
        (&uri[..idx], percent_decode(&uri[idx + 1..])?)
    } else {
        (uri, String::new())
    };
    
    let decoded = if main_part.contains('@') && !main_part.contains(':') {
        let parts: Vec<&str> = main_part.split('@').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid URI format"));
        }
        let userinfo = general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
        let userinfo = String::from_utf8(userinfo)?;
        format!("{}@{}", userinfo, parts[1])
    } else {
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(main_part)?;
        String::from_utf8(decoded)?
    };
    
    let (auth_part, server_part) = decoded.split_once('@')
        .ok_or_else(|| anyhow::anyhow!("Missing @ separator"))?;
    
    let (method, password) = auth_part.split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Missing : in auth part"))?;
    
    let (server, port_str) = server_part.rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Missing : in server part"))?;
    let port = port_str.parse::<u16>()?;
    
    Ok((method.to_string(), password.to_string(), server.to_string(), port))
}

pub fn encode_ss_uri(method: &str, password: &str, server: &str, port: u16, name: &str) -> String {
    let userinfo = format!("{}:{}", method, password);
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(userinfo.as_bytes());
    let mut uri = format!("ss://{}@{}:{}", encoded, server, port);
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&percent_encode(name));
    }
    uri
}

fn percent_encode(s: &str) -> String {
    percent_encoding::percent_encode(s.as_bytes(), percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn percent_decode(s: &str) -> Result<String> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|e| anyhow::anyhow!("Percent decode error: {}", e))
}