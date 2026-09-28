//! Web Push (RFC 8030/8291/8292) with VAPID, in pure Rust.

use crate::state::{log, AppState, Pending, PushSubscription};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use sha2::Sha256;

/// Returns (private scalar, uncompressed public point), both base64url.
pub fn generate_vapid() -> (String, String) {
    let sk = SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key().to_encoded_point(false);
    (B64URL.encode(sk.to_bytes()), B64URL.encode(pk.as_bytes()))
}

fn vapid_auth(private_b64: &str, public_b64: &str, endpoint: &str, contact: &str) -> Result<String> {
    let url = reqwest::Url::parse(endpoint)?;
    let aud = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    let header = B64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
    let exp = chrono::Utc::now().timestamp() + 12 * 3600;
    let claims = B64URL.encode(format!(r#"{{"aud":"{aud}","exp":{exp},"sub":"{contact}"}}"#));
    let signing_input = format!("{header}.{claims}");
    let sk = SigningKey::from_slice(&B64URL.decode(private_b64)?)?;
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let jwt = format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()));
    Ok(format!("vapid t={jwt}, k={public_b64}"))
}

/// aes128gcm content encoding (RFC 8291 / RFC 8188), single record.
fn encrypt(sub: &PushSubscription, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ua_public_bytes = B64URL.decode(&sub.keys.p256dh).context("p256dh")?;
    let auth = B64URL.decode(&sub.keys.auth).context("auth")?;
    let ua_public = PublicKey::from_sec1_bytes(&ua_public_bytes).context("subscriber key")?;
    let as_secret = p256::ecdh::EphemeralSecret::random(&mut rand::thread_rng());
    let as_public = as_secret.public_key().to_encoded_point(false);
    let shared = as_secret.diffie_hellman(&ua_public);

    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(&ua_public_bytes);
    key_info.extend_from_slice(as_public.as_bytes());
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&auth), shared.raw_secret_bytes()).expand(&key_info, &mut ikm).unwrap();

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let prk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek).unwrap();
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce).unwrap();

    let mut padded = plaintext.to_vec();
    padded.push(2); // last record delimiter
    let ct = Aes128Gcm::new(&cek.into()).encrypt(&Nonce::from(nonce), padded.as_ref()).map_err(|_| anyhow::anyhow!("encrypt"))?;

    let mut body = salt.to_vec();
    body.extend_from_slice(&4096u32.to_be_bytes());
    body.push(as_public.as_bytes().len() as u8);
    body.extend_from_slice(as_public.as_bytes());
    body.extend_from_slice(&ct);
    Ok(body)
}

pub async fn send(st: &AppState, sub: &PushSubscription, payload: &serde_json::Value) -> Result<()> {
    let (private, public) = {
        let p = st.persisted.lock().unwrap();
        (p.vapid_private.clone(), p.vapid_public.clone())
    };
    let auth = vapid_auth(&private, &public, &sub.endpoint, &st.cfg.push_contact)?;
    let body = encrypt(sub, payload.to_string().as_bytes())?;
    let resp = st
        .http
        .post(&sub.endpoint)
        .header("Authorization", auth)
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("TTL", "120")
        .header("Urgency", "high")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("push service returned {status}: {}", text.trim());
    }
    Ok(())
}

/// Push a "sign request waiting" notification to the device, if it subscribed.
pub async fn notify_device(st: &AppState, device_id: &str, req: &Pending) {
    let sub = {
        let p = st.persisted.lock().unwrap();
        p.devices.iter().find(|d| d.id == device_id).and_then(|d| d.push.clone())
    };
    let Some(sub) = sub else { return };
    let payload = serde_json::json!({
        "type": "sign",
        "id": req.id,
        "key": req.key.name,
        "user": req.ssh_user,
        "summary": req.process.iter().find(|p| p.name == "ssh" || p.name == "git").map(|p| p.args.clone()).unwrap_or_default(),
    });
    match send(st, &sub, &payload).await {
        Ok(()) => log(&format!("push: notified device for {}", req.id)),
        Err(e) => {
            log(&format!("push: {e}"));
            let gone = e.to_string().contains("404") || e.to_string().contains("410");
            if gone {
                let mut p = st.persisted.lock().unwrap();
                if let Some(d) = p.devices.iter_mut().find(|d| d.id == device_id) {
                    d.push = None;
                }
            }
        }
    }
}
