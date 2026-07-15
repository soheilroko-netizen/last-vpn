use anyhow::{bail, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::{AppConfig, Profile, ProxyStatus, ShadowTLSConfig, ShadowsocksConfig, TestResult};
use crate::shadowtls::{create_shadowtls_client, ShadowTlsClient, ShadowTlsConfig};
use crate::shadowsocks::{ShadowsocksClient, ShadowsocksLocal};

struct RunningProxy {
    profile: Profile,
    shadowtls_task: Option<tokio::task::JoinHandle<()>>,
    shadowsocks_task: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

pub struct ProxyManager {
    running: Arc<RwLock<Option<RunningProxy>>>,
    status_tx: mpsc::Sender<ProxyStatus>,
}

impl ProxyManager {
    pub fn new() -> Self {
        let (tx, _) = mpsc::channel(10);
        Self {
            running: Arc::new(RwLock::new(None)),
            status_tx: tx,
        }
    }

    pub async fn start(&mut self, profile: Profile) -> Result<()> {
        let local_port = profile.local_socks_port;
        let ss_port = local_port + 1;
        
        info!("Starting proxy: {} on port {} (ShadowTLS on {})", profile.name, local_port, ss_port);
        
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        
        // Build ShadowTLS config
        let stls_config = ShadowTLSConfig {
            server: profile.shadowtls.server.clone(),
            server_port: profile.shadowtls.server_port,
            version: profile.shadowtls.version,
            password: profile.shadowtls.password.clone(),
            tls: crate::config::ShadowTLSConfigTLS {
                enabled: profile.shadowtls.tls.enabled,
                server_name: profile.shadowtls.tls.server_name.clone(),
                insecure: profile.shadowtls.tls.insecure,
            },
        };
        
        // Build Shadowsocks config
        let ss_config = ShadowsocksConfig {
            cipher: profile.shadowsocks.cipher.clone(),
            password: profile.shadowsocks.password.clone(),
            server: "127.0.0.1".to_string(),
            port: ss_port,
            plugin: None,
            plugin_opts: None,
        };
        
        let _ = self.status_tx.send(ProxyStatus::Starting).await;
        
        // Connect ShadowTLS client
        let mut stls_client = create_shadowtls_client(stls_config.clone());
        stls_client.connect().await?;
        
        // Start Shadowsocks local server
        let ss_local = ShadowsocksLocal::new(ss_config, local_port, ss_port).await?;
        let profile_name = profile.name.clone();
        
        let ss_task = tokio::spawn(async move {
            if let Err(e) = ss_local.run().await {
                error!("Shadowsocks server error: {}", e);
            }
        });
        
        // Spawn ShadowTLS relay task
        let stls_task = tokio::spawn(async move {
            if let Err(e) = Self::relay_shadowtls(stls_client, ss_port, shutdown_rx).await {
                error!("ShadowTLS relay error: {}", e);
            }
        });
        
        let running = RunningProxy {
            profile,
            shadowtls_task: Some(stls_task),
            shadowsocks_task: Some(ss_task),
            shutdown_tx: Some(shutdown_tx),
        };
        
        *self.running.write().await = Some(running);
        
        let _ = self.status_tx.send(ProxyStatus::Running { 
            profile: profile_name, 
            local_port 
        }).await;
        
        info!("Proxy started successfully on port {}", local_port);
        Ok(())
    }
    
    async fn relay_shadowtls(mut client: Box<dyn ShadowTlsClient>, ss_port: u16, mut shutdown: mpsc::Receiver<()>) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", ss_port)).await?;
        info!("ShadowTLS relay listening on 127.0.0.1:{}", ss_port);
        
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("ShadowTLS relay shutting down");
                    break;
                }
                result = listener.accept() => {
                    let (mut local_stream, _) = result?;
                    let mut remote_client = client.clone();

                    tokio::spawn(async move {
                        let _ = Self::relay_connection(&mut local_stream, &mut *remote_client).await;
                    });
                }
            }
        }
        Ok(())
    }
    
    async fn relay_connection(local: &mut tokio::net::TcpStream, remote: &mut dyn ShadowTlsClient) -> Result<()> {
        let mut local_buf = [0u8; 16384];
        let mut remote_buf = [0u8; 16384];
        loop {
            tokio::select! {
                n = local.read(&mut local_buf) => {
                    let n = n?;
                    if n == 0 { break; }
                    remote.write(&local_buf[..n]).await?;
                }
                n = remote.read(&mut remote_buf) => {
                    let n = n?;
                    if n == 0 { break; }
                    local.write_all(&remote_buf[..n]).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping proxy");
        
        if let Some(running) = self.running.write().await.take() {
            if let Some(tx) = running.shutdown_tx {
                let _ = tx.send(()).await;
            }
            
            if let Some(task) = running.shadowtls_task {
                task.abort();
            }
            if let Some(task) = running.shadowsocks_task {
                task.abort();
            }
        }
        
        let _ = self.status_tx.send(ProxyStatus::Stopped).await;
        info!("Proxy stopped");
        Ok(())
    }

    pub async fn status(&self) -> ProxyStatus {
        self.running.read().await.as_ref()
            .map(|r| ProxyStatus::Running { 
                profile: r.profile.name.clone(), 
                local_port: r.profile.local_socks_port 
            })
            .unwrap_or(ProxyStatus::Stopped)
    }
}

pub async fn test_connection(profile: &Profile) -> TestResult {
    let start = std::time::Instant::now();
    
    // Build ShadowTLS config
    let stls_config = ShadowTLSConfig {
        server: profile.shadowtls.server.clone(),
        server_port: profile.shadowtls.server_port,
        version: profile.shadowtls.version,
        password: profile.shadowtls.password.clone(),
        tls: crate::config::ShadowTLSConfigTLS {
            enabled: profile.shadowtls.tls.enabled,
            server_name: profile.shadowtls.tls.server_name.clone(),
            insecure: profile.shadowtls.tls.insecure,
        },
    };
    
    let mut client = create_shadowtls_client(stls_config);
    
    if let Err(e) = client.connect().await {
        return TestResult {
            success: false,
            latency_ms: None,
            error: Some(format!("ShadowTLS connect failed: {}", e)),
        };
    }
    
    let latency = start.elapsed().as_millis() as u64;
    
    // Test Shadowsocks through the tunnel
    let ss_config = ShadowsocksConfig {
        cipher: profile.shadowsocks.cipher.clone(),
        password: profile.shadowsocks.password.clone(),
        server: "127.0.0.1".to_string(),
        port: profile.local_socks_port + 1,
        plugin: None,
        plugin_opts: None,
    };
    
    // Start temporary Shadowsocks server for test
    let test_port = profile.local_socks_port;
    let ss_local = match ShadowsocksLocal::new(ss_config, test_port, test_port + 1).await {
        Ok(s) => s,
        Err(e) => return TestResult {
            success: false,
            latency_ms: Some(latency),
            error: Some(format!("Shadowsocks setup failed: {}", e)),
        },
    };
    
    let ss_task = tokio::spawn(async move {
        let _ = ss_local.run().await;
    });
    
    // Give it a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    
    // Test through the proxy
    let test_result = match ShadowsocksClient::test_connection(test_port).await {
        Ok(_) => TestResult {
            success: true,
            latency_ms: Some(latency),
            error: None,
        },
        Err(e) => TestResult {
            success: false,
            latency_ms: Some(latency),
            error: Some(format!("Proxy test failed: {}", e)),
        },
    };
    
    ss_task.abort();
    let _ = client.close().await;
    
    test_result
}