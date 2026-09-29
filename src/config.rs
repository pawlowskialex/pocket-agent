use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Unix socket the agent listens on. Point IdentityAgent / SSH_AUTH_SOCK here.
    pub agent_socket: String,
    /// Another agent's socket (1Password, Secretive, ssh-agent...). Requests for keys the phone does not
    /// have are forwarded to it. Empty disables forwarding.
    pub upstream_socket: String,
    /// When the upstream agent holds a key the phone registered too, ask both and take the first
    /// signature, so a request can be approved on the phone or on the Mac. Off asks only the phone.
    pub ask_upstream_too: bool,
    /// Where registered devices, their public keys and the VAPID key pair are stored.
    pub state_file: String,

    /// Address to bind the web app to. Empty = the Mac's Tailscale IPv4.
    pub http_bind: String,
    pub http_port: u16,
    /// URL the phone uses. Default: https://<magicdns-name>:<port> (or http:// when tls is off).
    pub public_url: String,

    /// Serve HTTPS with a Tailscale certificate (needs HTTPS enabled for the tailnet).
    pub tls: bool,
    pub tls_cert: String,
    pub tls_key: String,
    /// Run `tailscale cert` to obtain/renew the certificate automatically.
    pub tls_auto: bool,

    /// Tailnet logins allowed to use the app. Default: the login of this node.
    pub allowed_logins: Vec<String>,
    /// Optional: restrict to specific tailnet device names (e.g. your phone).
    pub allowed_nodes: Vec<String>,
    /// Testing only: accept requests from loopback / this machine without a Tailscale identity.
    pub allow_local_api: bool,

    /// How long a signing request waits for the phone.
    pub sign_timeout_seconds: u64,
    /// Contact put into VAPID tokens ("mailto:" or "https:"). Apple rejects placeholder addresses.
    /// Empty = "mailto:<your tailnet login>" when that is an email address.
    pub push_contact: String,

    pub tailscale_bin: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            agent_socket: "~/.pocket-agent/agent.sock".into(),
            upstream_socket: String::new(),
            ask_upstream_too: true,
            state_file: "~/.pocket-agent/state.json".into(),
            http_bind: String::new(),
            http_port: 8420,
            public_url: String::new(),
            tls: true,
            tls_cert: "~/.pocket-agent/cert.pem".into(),
            tls_key: "~/.pocket-agent/key.pem".into(),
            tls_auto: true,
            allowed_logins: vec![],
            allowed_nodes: vec![],
            allow_local_api: false,
            sign_timeout_seconds: 120,
            push_contact: String::new(),
            tailscale_bin: find_tailscale(),
        }
    }
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

pub fn expand(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        return home().join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

pub fn default_config_path() -> PathBuf {
    if let Some(p) = std::env::var_os("POCKET_AGENT_CONFIG") {
        return PathBuf::from(p);
    }
    home().join(".config/pocket-agent/config.json")
}

pub fn find_tailscale() -> String {
    for c in ["/usr/local/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"] {
        if Path::new(c).exists() {
            return c.into();
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join("tailscale");
            if p.exists() {
                return p.to_string_lossy().into_owned();
            }
        }
    }
    "tailscale".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("config {} not found (run `pocket-agent init` first)", path.display())
            }
            Err(e) => return Err(e.into()),
        };
        let mut cfg: Config = serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        for f in [&mut cfg.agent_socket, &mut cfg.upstream_socket, &mut cfg.state_file, &mut cfg.tls_cert, &mut cfg.tls_key] {
            *f = expand(f);
        }
        if cfg.tailscale_bin.is_empty() {
            cfg.tailscale_bin = find_tailscale();
        }
        if cfg.sign_timeout_seconds == 0 {
            cfg.sign_timeout_seconds = 120;
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }
}
