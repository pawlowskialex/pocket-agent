use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Default)]
pub struct TsSelf {
    pub ips: Vec<String>,
    pub dns_name: String,
    pub login: String,
    pub cert_domains: Vec<String>,
}

pub async fn self_info(bin: &str) -> Result<TsSelf> {
    let out = Command::new(bin).args(["status", "--self", "--json"]).output().await.context("run tailscale status")?;
    if !out.status.success() {
        bail!("tailscale status failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    #[derive(Deserialize)]
    struct Status {
        #[serde(rename = "Self")]
        this: Node,
        #[serde(rename = "User", default)]
        users: HashMap<String, User>,
        #[serde(rename = "CertDomains", default)]
        cert_domains: Option<Vec<String>>,
    }
    #[derive(Deserialize)]
    struct Node {
        #[serde(rename = "DNSName")]
        dns_name: String,
        #[serde(rename = "TailscaleIPs", default)]
        ips: Vec<String>,
        #[serde(rename = "UserID")]
        user_id: i64,
    }
    #[derive(Deserialize)]
    struct User {
        #[serde(rename = "LoginName")]
        login: String,
    }
    let st: Status = serde_json::from_slice(&out.stdout)?;
    Ok(TsSelf {
        ips: st.this.ips,
        dns_name: st.this.dns_name.trim_end_matches('.').to_string(),
        login: st.users.get(&st.this.user_id.to_string()).map(|u| u.login.clone()).unwrap_or_default(),
        cert_domains: st.cert_domains.unwrap_or_default(),
    })
}

#[derive(Debug, Clone)]
pub struct Whois {
    pub login: String,
    pub node: String,
}

pub struct WhoisCache {
    bin: String,
    cache: Mutex<HashMap<String, (Instant, Result<Whois, String>)>>,
}

impl WhoisCache {
    pub fn new(bin: &str) -> Self {
        WhoisCache { bin: bin.into(), cache: Mutex::new(HashMap::new()) }
    }

    pub async fn lookup(&self, ip: &str) -> Result<Whois, String> {
        if let Some((at, res)) = self.cache.lock().await.get(ip) {
            if at.elapsed() < Duration::from_secs(120) {
                return res.clone();
            }
        }
        let res = self.query(ip).await.map_err(|e| e.to_string());
        self.cache.lock().await.insert(ip.to_string(), (Instant::now(), res.clone()));
        res
    }

    async fn query(&self, ip: &str) -> Result<Whois> {
        let out = Command::new(&self.bin).args(["whois", "--json", ip]).output().await?;
        if !out.status.success() {
            bail!("tailscale whois {}: {}", ip, String::from_utf8_lossy(&out.stderr).trim());
        }
        #[derive(Deserialize)]
        struct R {
            #[serde(rename = "Node")]
            node: N,
            #[serde(rename = "UserProfile")]
            user: U,
        }
        #[derive(Deserialize)]
        struct N {
            #[serde(rename = "Name", default)]
            name: String,
            #[serde(rename = "ComputedName", default)]
            computed: String,
        }
        #[derive(Deserialize)]
        struct U {
            #[serde(rename = "LoginName", default)]
            login: String,
        }
        let r: R = serde_json::from_slice(&out.stdout)?;
        let node = if r.node.computed.is_empty() { r.node.name.trim_end_matches('.').to_string() } else { r.node.computed };
        Ok(Whois { login: r.user.login, node })
    }
}

/// Obtain or renew the Tailscale HTTPS certificate for `domain`.
pub async fn ensure_cert(bin: &str, domain: &str, cert: &str, key: &str) -> Result<()> {
    if let Some(dir) = Path::new(cert).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let out = Command::new(bin).args(["cert", "--cert-file", cert, "--key-file", key, domain]).output().await?;
    if !out.status.success() {
        bail!("tailscale cert failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
