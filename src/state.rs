use crate::config::Config;
use crate::tailscale::{TsSelf, WhoisCache};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::sync::{oneshot, Notify};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PushSubscription {
    pub endpoint: String,
    pub keys: PushKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PushKeys {
    pub p256dh: String,
    pub auth: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredKey {
    pub fingerprint: String,
    pub name: String,
    #[serde(rename = "type")]
    pub key_type: String,
    /// SSH public key blob, base64.
    pub blob: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub keys: Vec<RegisteredKey>,
    #[serde(default)]
    pub push: Option<PushSubscription>,
    #[serde(default)]
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Persisted {
    #[serde(default)]
    pub vapid_private: String,
    #[serde(default)]
    pub vapid_public: String,
    #[serde(default)]
    pub devices: Vec<Device>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Proc {
    pub pid: i32,
    pub name: String,
    pub args: String,
}

/// A signing request waiting for the phone.
pub struct Pending {
    pub id: String,
    pub created: chrono::DateTime<chrono::Local>,
    pub device_id: String,
    pub key: RegisteredKey,
    /// Signature algorithm the phone must use (ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-256/512).
    pub algorithm: String,
    pub data: Vec<u8>,
    pub ssh_user: String,
    pub process: Vec<Proc>,
    pub tx: Mutex<Option<oneshot::Sender<Result<Vec<u8>, String>>>>,
}

#[derive(Serialize)]
pub struct PendingView {
    pub id: String,
    pub created: String,
    pub key_fingerprint: String,
    pub key_name: String,
    pub key_type: String,
    pub algorithm: String,
    pub data: String,
    pub ssh_user: String,
    pub process: Vec<Proc>,
}

impl Pending {
    pub fn view(&self) -> PendingView {
        PendingView {
            id: self.id.clone(),
            created: self.created.to_rfc3339(),
            key_fingerprint: self.key.fingerprint.clone(),
            key_name: self.key.name.clone(),
            key_type: self.key.key_type.clone(),
            algorithm: self.algorithm.clone(),
            data: B64.encode(&self.data),
            ssh_user: self.ssh_user.clone(),
            process: self.process.clone(),
        }
    }
}

pub struct AppState {
    pub cfg: Config,
    pub ts: TsSelf,
    pub public_url: String,
    pub whois: WhoisCache,
    pub persisted: Mutex<Persisted>,
    pub pending: Mutex<Vec<std::sync::Arc<Pending>>>,
    pub notify: Notify,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn load_persisted(path: &str) -> Result<Persisted> {
        let mut p: Persisted = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
            Err(e) => return Err(e.into()),
        };
        if p.vapid_private.is_empty() {
            let (private, public) = crate::push::generate_vapid();
            p.vapid_private = private;
            p.vapid_public = public;
        }
        Ok(p)
    }

    pub fn save_persisted(&self) -> Result<()> {
        let p = self.persisted.lock().unwrap();
        let path = PathBuf::from(&self.cfg.state_file);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&*p)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// All keys registered by any device, with the owning device id.
    pub fn registered_keys(&self) -> Vec<(String, RegisteredKey)> {
        let p = self.persisted.lock().unwrap();
        let mut out = vec![];
        for d in &p.devices {
            for k in &d.keys {
                if !out.iter().any(|(_, o): &(String, RegisteredKey)| o.fingerprint == k.fingerprint) {
                    out.push((d.id.clone(), k.clone()));
                }
            }
        }
        out
    }

    pub fn find_key_by_blob(&self, blob: &[u8]) -> Option<(String, RegisteredKey)> {
        let want = B64.encode(blob);
        self.registered_keys().into_iter().find(|(_, k)| k.blob == want)
    }

    pub fn pending_for(&self, device_id: Option<&str>) -> Vec<PendingView> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .filter(|p| device_id.map_or(true, |d| p.device_id == d))
            .map(|p| p.view())
            .collect()
    }

    pub fn take_pending(&self, id: &str) -> Option<std::sync::Arc<Pending>> {
        let mut v = self.pending.lock().unwrap();
        let idx = v.iter().position(|p| p.id == id)?;
        let p = v.remove(idx);
        self.notify.notify_waiters();
        Some(p)
    }
}

pub fn rand_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn fingerprint(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("SHA256:{}", B64URL.encode(Sha256::digest(blob)).replace('-', "+").replace('_', "/"))
}

pub fn log(msg: &str) {
    eprintln!("{} {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
}
