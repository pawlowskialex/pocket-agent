//! SSH agent protocol on a unix socket. Registered (phone) keys are signed by forwarding the
//! challenge to the phone; everything else is proxied to the upstream agent, if any. When the
//! upstream agent holds a registered key as well, both are asked and the first signature wins.

use crate::state::{log, rand_hex, AppState, Pending, Proc};
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
const FLAG_RSA_SHA2_256: u32 = 2;
const FLAG_RSA_SHA2_512: u32 = 4;

pub async fn run(st: Arc<AppState>) -> Result<()> {
    let path = &st.cfg.agent_socket;
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    log(&format!("agent: listening on {} (fallback {})", path, st.cfg.upstream_socket));
    loop {
        let (stream, _) = listener.accept().await?;
        let st = st.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, st).await {
                if !e.to_string().contains("eof") {
                    log(&format!("agent: connection ended: {e}"));
                }
            }
        });
    }
}

async fn read_msg(s: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    if s.read_exact(&mut len).await.is_err() {
        bail!("eof");
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 1 << 20 {
        bail!("bad agent message length {n}");
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_msg(s: &mut UnixStream, msg: &[u8]) -> Result<()> {
    s.write_all(&(msg.len() as u32).to_be_bytes()).await?;
    s.write_all(msg).await?;
    Ok(())
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn get_string<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    if *pos + 4 > buf.len() {
        bail!("short read");
    }
    let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + n > buf.len() {
        bail!("short read");
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

fn get_u32(buf: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > buf.len() {
        bail!("short read");
    }
    let v = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

struct Upstream {
    path: String,
    conn: Option<UnixStream>,
    failed: bool,
}

impl Upstream {
    async fn roundtrip(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if self.path.is_empty() || self.failed {
            return None;
        }
        if self.conn.is_none() {
            match tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&self.path)).await {
                Ok(Ok(c)) => self.conn = Some(c),
                _ => {
                    self.failed = true;
                    return None;
                }
            }
        }
        let c = self.conn.as_mut().unwrap();
        if write_msg(c, msg).await.is_err() {
            self.conn = None;
            return None;
        }
        match read_msg(c).await {
            Ok(r) => Some(r),
            Err(_) => {
                self.conn = None;
                None
            }
        }
    }

    /// The keys the upstream agent offers right now: (blob, comment).
    async fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
        let Some(resp) = self.roundtrip(&[REQUEST_IDENTITIES]).await else { return vec![] };
        parse_identities(&resp)
    }
}

fn parse_identities(resp: &[u8]) -> Vec<(Vec<u8>, String)> {
    let mut out = vec![];
    if resp.first() != Some(&IDENTITIES_ANSWER) {
        return out;
    }
    let mut pos = 1;
    let Ok(n) = get_u32(resp, &mut pos) else { return out };
    for _ in 0..n {
        let (Ok(blob), Ok(comment)) = (get_string(resp, &mut pos), get_string(resp, &mut pos)) else { break };
        out.push((blob.to_vec(), String::from_utf8_lossy(comment).into_owned()));
    }
    out
}

/// Ask the upstream agent to sign, on a connection of its own so it can be abandoned when the
/// phone answers first. Anything that is not a signature never resolves: a locked or unhelpful
/// upstream must not lose the race on the phone's behalf.
async fn upstream_sign(path: String, msg: Vec<u8>) -> Vec<u8> {
    let mut up = Upstream { path, conn: None, failed: false };
    match up.roundtrip(&msg).await {
        Some(r) if r.first() == Some(&SIGN_RESPONSE) => r,
        _ => std::future::pending().await,
    }
}

/// Which side answered a race between the phone and the upstream agent.
enum Answer {
    Phone(Result<Result<Vec<u8>, String>, oneshot::error::RecvError>),
    Upstream(Vec<u8>),
}

async fn handle(mut s: UnixStream, st: Arc<AppState>) -> Result<()> {
    let chain = process_chain(peer_pid(&s));
    let mut up = Upstream { path: st.cfg.upstream_socket.clone(), conn: None, failed: false };
    loop {
        let msg = read_msg(&mut s).await?;
        let reply = match msg[0] {
            REQUEST_IDENTITIES => list_identities(&st, &mut up).await,
            SIGN_REQUEST => match sign(&st, &mut up, &msg, &chain).await {
                Ok(r) => r,
                Err(e) => {
                    log(&format!("agent: sign failed: {e}"));
                    vec![FAILURE]
                }
            },
            _ => up.roundtrip(&msg).await.unwrap_or_else(|| vec![FAILURE]),
        };
        write_msg(&mut s, &reply).await?;
    }
}

async fn list_identities(st: &AppState, up: &mut Upstream) -> Vec<u8> {
    let mut keys: Vec<(Vec<u8>, String)> = st
        .registered_keys()
        .into_iter()
        .filter_map(|(_, k)| B64.decode(&k.blob).ok().map(|b| (b, k.name)))
        .collect();
    for (blob, comment) in up.identities().await {
        if !keys.iter().any(|(b, _)| *b == blob) {
            keys.push((blob, comment));
        }
    }
    let mut out = vec![IDENTITIES_ANSWER];
    out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for (blob, comment) in keys {
        put_string(&mut out, &blob);
        put_string(&mut out, comment.as_bytes());
    }
    out
}

async fn sign(st: &Arc<AppState>, up: &mut Upstream, msg: &[u8], chain: &[Proc]) -> Result<Vec<u8>> {
    let mut pos = 1;
    let blob = get_string(msg, &mut pos)?.to_vec();
    let data = get_string(msg, &mut pos)?.to_vec();
    let flags = get_u32(msg, &mut pos).unwrap_or(0);

    let Some((device_id, key)) = st.find_key_by_blob(&blob) else {
        return Ok(up.roundtrip(msg).await.unwrap_or_else(|| vec![FAILURE]));
    };
    let algorithm = match key.key_type.as_str() {
        "ssh-rsa" => {
            if flags & FLAG_RSA_SHA2_512 != 0 {
                "rsa-sha2-512".to_string()
            } else if flags & FLAG_RSA_SHA2_256 != 0 {
                "rsa-sha2-256".to_string()
            } else {
                bail!("client asked for an ssh-rsa (SHA-1) signature, which the phone does not do");
            }
        }
        t => t.to_string(),
    };

    // The upstream agent may hold the very same key (the phone's copy of a 1Password key, say).
    // Then ask it too, so whichever of the two is in front of you can approve the request.
    let also_upstream = st.cfg.ask_upstream_too && up.identities().await.iter().any(|(b, _)| *b == blob);

    let (tx, rx) = oneshot::channel();
    let req = Arc::new(Pending {
        id: rand_hex(8),
        created: chrono::Local::now(),
        device_id: device_id.clone(),
        key: key.clone(),
        algorithm,
        data,
        ssh_user: userauth_user(msg),
        process: chain.to_vec(),
        tx: std::sync::Mutex::new(Some(tx)),
    });
    st.pending.lock().unwrap().push(req.clone());
    st.notify.notify_waiters();
    let asked = if also_upstream { "phone and upstream" } else { "phone" };
    log(&format!("agent: {} waiting for {}: key={:?} user={:?} proc={}", req.id, asked, key.name, req.ssh_user, summarize(chain)));
    {
        let st = st.clone();
        let req = req.clone();
        tokio::spawn(async move { crate::push::notify_device(&st, &device_id, &req).await });
    }

    // First answer wins. From the phone that includes a denial; from upstream only a signature,
    // since its failures (locked vault, no such key) are not the same as "you said no".
    let race = async {
        if also_upstream {
            tokio::select! {
                r = rx => Answer::Phone(r),
                sig = upstream_sign(st.cfg.upstream_socket.clone(), msg.to_vec()) => Answer::Upstream(sig),
            }
        } else {
            Answer::Phone(rx.await)
        }
    };
    let res = tokio::time::timeout(Duration::from_secs(st.cfg.sign_timeout_seconds), race).await;
    st.take_pending(&req.id);
    match res {
        Ok(Answer::Phone(Ok(Ok(sig_blob)))) => {
            log(&format!("agent: {} signed by phone with {:?}", req.id, key.name));
            let mut out = vec![SIGN_RESPONSE];
            put_string(&mut out, &sig_blob);
            Ok(out)
        }
        Ok(Answer::Upstream(reply)) => {
            log(&format!("agent: {} signed by the upstream agent with {:?}", req.id, key.name));
            Ok(reply)
        }
        Ok(Answer::Phone(Ok(Err(e)))) => bail!("{} {}", req.id, e),
        Ok(Answer::Phone(Err(_))) => bail!("{} request dropped", req.id),
        Err(_) if also_upstream => bail!("{} neither the phone nor the upstream agent answered in time", req.id),
        Err(_) => bail!("{} phone did not answer in time", req.id),
    }
}

/// Extract the user name from an SSH_MSG_USERAUTH_REQUEST signing blob, if that is what it is.
fn userauth_user(msg: &[u8]) -> String {
    let mut pos = 1;
    let _blob = get_string(msg, &mut pos).ok();
    let Ok(data) = get_string(msg, &mut pos) else { return String::new() };
    let mut p = 0;
    let Ok(_session) = get_string(data, &mut p) else { return String::new() };
    if data.get(p) != Some(&50) {
        return String::new();
    }
    p += 1;
    get_string(data, &mut p).map(|u| String::from_utf8_lossy(u).into_owned()).unwrap_or_default()
}

fn peer_pid(s: &UnixStream) -> i32 {
    let fd = s.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SOL_LOCAL = 0, LOCAL_PEERPID = 2 on macOS.
    let rc = unsafe { libc::getsockopt(fd, 0, 2, &mut pid as *mut _ as *mut libc::c_void, &mut len) };
    if rc == 0 {
        pid
    } else {
        0
    }
}

fn process_chain(mut pid: i32) -> Vec<Proc> {
    let mut chain = vec![];
    for _ in 0..12 {
        if pid <= 1 {
            break;
        }
        let Ok(out) = std::process::Command::new("ps").args(["-o", "ppid=,args=", "-p", &pid.to_string()]).output() else { break };
        let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if line.is_empty() {
            break;
        }
        let (ppid, args) = line.split_once(' ').unwrap_or((&line, ""));
        let Ok(ppid) = ppid.trim().parse::<i32>() else { break };
        let args = args.trim();
        let exe = args.split(' ').next().unwrap_or("");
        let name = exe.rsplit('/').next().unwrap_or(exe).to_string();
        let mut args = args.to_string();
        if args.len() > 300 {
            args.truncate(300);
            args.push('…');
        }
        chain.push(Proc { pid, name, args });
        pid = ppid;
    }
    chain
}

fn summarize(chain: &[Proc]) -> String {
    chain.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(" < ")
}

/// Wrap a raw signature from the phone into an SSH signature blob.
pub fn ssh_signature_blob(algorithm: &str, raw: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![];
    put_string(&mut out, algorithm.as_bytes());
    if algorithm.starts_with("ecdsa-sha2-") {
        // WebCrypto gives r || s, fixed width; SSH wants string(mpint r, mpint s).
        if raw.len() % 2 != 0 {
            bail!("bad ECDSA signature length");
        }
        let (r, s) = raw.split_at(raw.len() / 2);
        let mut inner = vec![];
        put_string(&mut inner, &mpint(r));
        put_string(&mut inner, &mpint(s));
        put_string(&mut out, &inner);
    } else {
        put_string(&mut out, raw);
    }
    Ok(out)
}

fn mpint(b: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < b.len() && b[i] == 0 {
        i += 1;
    }
    let b = &b[i..];
    if b.first().map_or(false, |x| x & 0x80 != 0) {
        let mut v = vec![0u8];
        v.extend_from_slice(b);
        v
    } else {
        b.to_vec()
    }
}
