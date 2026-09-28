use crate::state::{log, AppState, Device, PushSubscription, RegisteredKey};
use anyhow::Result;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

type St = State<Arc<AppState>>;

macro_rules! asset {
    ($path:literal, $ct:literal) => {
        get(|| async { ([(header::CONTENT_TYPE, HeaderValue::from_static($ct)), (header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))], include_bytes!(concat!("../web/", $path)).as_slice()) })
    };
}

pub fn router(st: Arc<AppState>) -> Router {
    Router::new()
        .route("/", asset!("index.html", "text/html; charset=utf-8"))
        .route("/app.js", asset!("app.js", "text/javascript; charset=utf-8"))
        .route("/sshkey.js", asset!("sshkey.js", "text/javascript; charset=utf-8"))
        .route("/sw.js", asset!("sw.js", "text/javascript; charset=utf-8"))
        .route("/manifest.webmanifest", asset!("manifest.webmanifest", "application/manifest+json"))
        .route("/icon.svg", asset!("icon.svg", "image/svg+xml"))
        .route("/icon-180.png", asset!("icon-180.png", "image/png"))
        .route("/icon-512.png", asset!("icon-512.png", "image/png"))
        .route("/api/state", get(state))
        .route("/api/devices/{id}", put(put_device).delete(delete_device))
        .route("/api/devices/{id}/push-test", post(push_test))
        .route("/api/requests", get(requests))
        .route("/api/requests/{id}/signature", post(signature))
        .route("/api/requests/{id}/deny", post(deny))
        .layer(middleware::from_fn_with_state(st.clone(), authenticate))
        .with_state(st)
}

/// Only admit connections Tailscale can attribute to an allowed login (and optionally node).
/// Connections from this machine are rejected unless allow_local_api is set.
async fn authenticate(State(st): St, ConnectInfo(addr): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    let ip = addr.ip();
    let ip_s = ip.to_string();
    let client = if ip.is_loopback() || st.ts.ips.iter().any(|i| *i == ip_s) {
        if !st.cfg.allow_local_api {
            return (StatusCode::FORBIDDEN, "local API access disabled").into_response();
        }
        "localhost".to_string()
    } else {
        match st.whois.lookup(&ip_s).await {
            Err(e) => {
                log(&format!("web: reject {ip_s}: {e}"));
                return (StatusCode::FORBIDDEN, "not a tailnet peer").into_response();
            }
            Ok(w) => {
                if !st.cfg.allowed_logins.iter().any(|l| l.eq_ignore_ascii_case(&w.login)) {
                    log(&format!("web: reject {ip_s}: login {:?} not allowed", w.login));
                    return (StatusCode::FORBIDDEN, "login not allowed").into_response();
                }
                if !st.cfg.allowed_nodes.is_empty() && !st.cfg.allowed_nodes.iter().any(|n| n.eq_ignore_ascii_case(&w.node)) {
                    log(&format!("web: reject {ip_s}: node {:?} not allowed", w.node));
                    return (StatusCode::FORBIDDEN, "device not allowed").into_response();
                }
                if w.node.is_empty() { w.login } else { w.node }
            }
        }
    };
    req.headers_mut().insert("x-client", HeaderValue::from_str(&client).unwrap_or(HeaderValue::from_static("?")));
    next.run(req).await
}

fn client(req: &axum::http::HeaderMap) -> String {
    req.get("x-client").and_then(|v| v.to_str().ok()).unwrap_or("?").to_string()
}

async fn state(State(st): St, headers: axum::http::HeaderMap) -> Json<serde_json::Value> {
    let (vapid, devices) = {
        let p = st.persisted.lock().unwrap();
        (p.vapid_public.clone(), p.devices.clone())
    };
    let registered: Vec<String> = devices.iter().flat_map(|d| d.keys.iter().map(|k| k.fingerprint.clone())).collect();
    let upstream = crate::upstream_keys(&st.cfg.upstream_socket).await;
    Json(serde_json::json!({
        "host": st.ts.dns_name,
        "public_url": st.public_url,
        "client": client(&headers),
        "vapid_public": vapid,
        "devices": devices.iter().map(|d| serde_json::json!({"id": d.id, "name": d.name, "keys": d.keys.len(), "push": d.push.is_some(), "last_seen": d.last_seen})).collect::<Vec<_>>(),
        "pending": st.pending_for(None).len(),
        "upstream_ok": upstream.is_some(),
        "upstream": upstream.unwrap_or_default().into_iter().map(|(blob, name)| {
            let fp = crate::state::fingerprint(&blob);
            serde_json::json!({"fingerprint": fp, "name": name, "type": blob_type(&blob), "registered": registered.contains(&fp)})
        }).collect::<Vec<_>>(),
    }))
}

fn blob_type(blob: &[u8]) -> String {
    if blob.len() < 4 {
        return String::new();
    }
    let n = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    blob.get(4..4 + n).map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default()
}

#[derive(Deserialize)]
struct DeviceIn {
    name: String,
    #[serde(default)]
    keys: Vec<RegisteredKey>,
    #[serde(default)]
    push: Option<PushSubscription>,
}

async fn put_device(State(st): St, Path(id): Path<String>, headers: axum::http::HeaderMap, Json(inp): Json<DeviceIn>) -> Response {
    if id.len() < 8 || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return (StatusCode::BAD_REQUEST, "bad device id").into_response();
    }
    let mut keys = vec![];
    for k in inp.keys {
        let Ok(blob) = B64.decode(&k.blob) else { return (StatusCode::BAD_REQUEST, "bad key blob").into_response() };
        let fp = crate::state::fingerprint(&blob);
        if fp != k.fingerprint {
            return (StatusCode::BAD_REQUEST, format!("fingerprint mismatch for {}", k.name)).into_response();
        }
        let key_type = blob_type(&blob);
        if !["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"].contains(&key_type.as_str()) {
            return (StatusCode::BAD_REQUEST, format!("unsupported key type {key_type}")).into_response();
        }
        keys.push(RegisteredKey { fingerprint: fp, name: k.name, key_type, blob: k.blob });
    }
    let n = keys.len();
    {
        let mut p = st.persisted.lock().unwrap();
        let dev = Device { id: id.clone(), name: inp.name, keys, push: inp.push, last_seen: chrono::Local::now().to_rfc3339() };
        match p.devices.iter_mut().find(|d| d.id == id) {
            Some(d) => *d = dev,
            None => p.devices.push(dev),
        }
    }
    if let Err(e) = st.save_persisted() {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    log(&format!("web: device {} ({}) registered {} key(s)", &id[..8], client(&headers), n));
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_device(State(st): St, Path(id): Path<String>, headers: axum::http::HeaderMap) -> Response {
    st.persisted.lock().unwrap().devices.retain(|d| d.id != id);
    let _ = st.save_persisted();
    log(&format!("web: device {} removed by {}", id.get(..8).unwrap_or(&id), client(&headers)));
    StatusCode::NO_CONTENT.into_response()
}

async fn push_test(State(st): St, Path(id): Path<String>) -> Response {
    let sub = st.persisted.lock().unwrap().devices.iter().find(|d| d.id == id).and_then(|d| d.push.clone());
    let Some(sub) = sub else { return (StatusCode::NOT_FOUND, "device has no push subscription").into_response() };
    match crate::push::send(&st, &sub, &serde_json::json!({"type": "test"})).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct RequestsQuery {
    device: Option<String>,
    #[serde(default)]
    wait: u64,
}

/// Long-poll for pending signing requests for a device.
async fn requests(State(st): St, Query(q): Query<RequestsQuery>) -> Json<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait.min(30));
    loop {
        let pending = st.pending_for(q.device.as_deref());
        if !pending.is_empty() || tokio::time::Instant::now() >= deadline {
            return Json(serde_json::json!({ "requests": pending }));
        }
        let _ = tokio::time::timeout(Duration::from_millis(500), st.notify.notified()).await;
    }
}

#[derive(Deserialize)]
struct SignatureIn {
    signature: String,
    #[serde(default)]
    algorithm: String,
}

async fn signature(State(st): St, Path(id): Path<String>, headers: axum::http::HeaderMap, Json(inp): Json<SignatureIn>) -> Response {
    let Some(req) = st.take_pending(&id) else { return (StatusCode::NOT_FOUND, "no such pending request").into_response() };
    let raw = match B64.decode(&inp.signature) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad signature encoding").into_response(),
    };
    if !inp.algorithm.is_empty() && inp.algorithm != req.algorithm {
        return (StatusCode::BAD_REQUEST, format!("expected {} signature", req.algorithm)).into_response();
    }
    let blob = match crate::agent::ssh_signature_blob(&req.algorithm, &raw) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if let Some(tx) = req.tx.lock().unwrap().take() {
        let _ = tx.send(Ok(blob));
    }
    log(&format!("web: {} signature received from {}", id, client(&headers)));
    StatusCode::NO_CONTENT.into_response()
}

async fn deny(State(st): St, Path(id): Path<String>, headers: axum::http::HeaderMap) -> Response {
    let Some(req) = st.take_pending(&id) else { return (StatusCode::NOT_FOUND, "no such pending request").into_response() };
    if let Some(tx) = req.tx.lock().unwrap().take() {
        let _ = tx.send(Err(format!("denied from {}", client(&headers))));
    }
    log(&format!("web: {} denied by {}", id, client(&headers)));
    StatusCode::NO_CONTENT.into_response()
}

pub async fn serve(st: Arc<AppState>, addr: SocketAddr) -> Result<()> {
    let app = router(st.clone()).into_make_service_with_connect_info::<SocketAddr>();
    if st.cfg.tls {
        let tls = RustlsConfig::from_pem_file(&st.cfg.tls_cert, &st.cfg.tls_key).await?;
        if st.cfg.tls_auto {
            let tls = tls.clone();
            let st = st.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                    match crate::tailscale::ensure_cert(&st.cfg.tailscale_bin, &st.ts.dns_name, &st.cfg.tls_cert, &st.cfg.tls_key).await {
                        Ok(()) => {
                            if let Err(e) = tls.reload_from_pem_file(&st.cfg.tls_cert, &st.cfg.tls_key).await {
                                log(&format!("tls: reload failed: {e}"));
                            }
                        }
                        Err(e) => log(&format!("tls: renew failed: {e}")),
                    }
                }
            });
        }
        axum_server::bind_rustls(addr, tls).serve(app).await?;
    } else {
        axum_server::bind(addr).serve(app).await?;
    }
    Ok(())
}
