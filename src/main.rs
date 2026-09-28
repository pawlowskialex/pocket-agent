mod agent;
mod config;
mod push;
mod state;
mod tailscale;
mod web;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use state::{log, AppState};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const LAUNCHD_LABEL: &str = "io.github.pawlowskialex.pocket-agent";

#[derive(Parser)]
#[command(name = "pocket-agent", about = "SSH agent for macOS that keeps the private keys on your phone.")]
struct Cli {
    /// Config file (default $POCKET_AGENT_CONFIG or ~/.config/pocket-agent/config.json)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a config file with values detected from Tailscale
    Init,
    /// Run the agent and the web app (foreground)
    Serve,
    /// Obtain or renew the Tailscale HTTPS certificate now
    Cert,
    /// Install and start a launchd agent that runs `serve`
    Install,
    /// Stop and remove the launchd agent
    Uninstall,
    /// Print the ~/.ssh/config snippet that points ssh at this agent
    SshConfig,
    /// Print URLs, sockets, and registered devices
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.config.unwrap_or_else(config::default_config_path);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        match cli.cmd {
            Cmd::Init => cmd_init(&path).await,
            Cmd::Serve => cmd_serve(&path).await,
            Cmd::Cert => cmd_cert(&path).await,
            Cmd::Install => cmd_install(&path),
            Cmd::Uninstall => cmd_uninstall(),
            Cmd::SshConfig => cmd_ssh_config(&path),
            Cmd::Status => cmd_status(&path).await,
        }
    })
}

async fn cmd_init(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        bail!("{} already exists; edit it or delete it first", path.display());
    }
    let mut cfg = Config::default();
    cfg.upstream_socket = detect_upstream().unwrap_or_default();
    let ts = tailscale::self_info(&cfg.tailscale_bin).await?;
    cfg.allowed_logins = vec![ts.login.clone()];
    cfg.tls = ts.cert_domains.iter().any(|d| *d == ts.dns_name);
    cfg.public_url = format!("{}://{}:{}", if cfg.tls { "https" } else { "http" }, ts.dns_name, cfg.http_port);
    cfg.save(path)?;
    println!("wrote {}", path.display());
    match cfg.upstream_socket.as_str() {
        "" => println!("no other agent found; keys not on the phone will be refused (set upstream_socket to change)"),
        s => println!("forwarding keys the phone does not have to {s}"),
    }
    println!("app URL: {} (for tailnet devices logged in as {})", cfg.public_url, ts.login);
    if cfg.tls {
        cmd_cert_with(&cfg, &ts).await?;
    } else {
        println!("HTTPS is not enabled for this tailnet; serving plain http (push notifications need https).");
    }
    Ok(())
}

async fn cmd_cert(path: &std::path::Path) -> Result<()> {
    let cfg = Config::load(path)?;
    let ts = tailscale::self_info(&cfg.tailscale_bin).await?;
    cmd_cert_with(&cfg, &ts).await
}

async fn cmd_cert_with(cfg: &Config, ts: &tailscale::TsSelf) -> Result<()> {
    // `init` works on an unloaded Config whose paths may still contain "~".
    let (cert, key) = (config::expand(&cfg.tls_cert), config::expand(&cfg.tls_key));
    tailscale::ensure_cert(&cfg.tailscale_bin, &ts.dns_name, &cert, &key).await?;
    println!("certificate for {} written to {}", ts.dns_name, cert);
    Ok(())
}

async fn resolve(cfg: &mut Config) -> Result<(tailscale::TsSelf, SocketAddr, String)> {
    let ts = tailscale::self_info(&cfg.tailscale_bin).await?;
    let bind = if cfg.http_bind.is_empty() {
        ts.ips.iter().find(|ip| ip.contains('.')).cloned().context("no Tailscale IPv4 address; set http_bind")?
    } else {
        cfg.http_bind.clone()
    };
    let addr: SocketAddr = format!("{bind}:{}", cfg.http_port).parse()?;
    let public = if cfg.public_url.is_empty() {
        format!("{}://{}:{}", if cfg.tls { "https" } else { "http" }, ts.dns_name, cfg.http_port)
    } else {
        cfg.public_url.trim_end_matches('/').to_string()
    };
    if cfg.allowed_logins.is_empty() && !ts.login.is_empty() {
        cfg.allowed_logins = vec![ts.login.clone()];
    }
    if cfg.push_contact.is_empty() {
        cfg.push_contact = if ts.login.contains('@') { format!("mailto:{}", ts.login) } else { "https://github.com/pawlowskialex/pocket-agent".into() };
    }
    Ok((ts, addr, public))
}

async fn cmd_serve(path: &std::path::Path) -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().ok();
    let mut cfg = Config::load(path)?;
    let (ts, addr, public) = resolve(&mut cfg).await?;
    if cfg.tls && cfg.tls_auto && !std::path::Path::new(&cfg.tls_cert).exists() {
        tailscale::ensure_cert(&cfg.tailscale_bin, &ts.dns_name, &cfg.tls_cert, &cfg.tls_key).await?;
    }
    let persisted = AppState::load_persisted(&cfg.state_file)?;
    let st = Arc::new(AppState {
        whois: tailscale::WhoisCache::new(&cfg.tailscale_bin),
        persisted: Mutex::new(persisted),
        pending: Mutex::new(vec![]),
        notify: tokio::sync::Notify::new(),
        http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build()?,
        public_url: public.clone(),
        ts,
        cfg,
    });
    st.save_persisted()?;
    log(&format!(
        "web: app on {} (public URL {}, tls {}, allowed logins {:?}, nodes {:?}, local api {})",
        addr, public, st.cfg.tls, st.cfg.allowed_logins, st.cfg.allowed_nodes, st.cfg.allow_local_api
    ));
    let a = tokio::spawn(agent::run(st.clone()));
    let w = tokio::spawn(web::serve(st.clone(), addr));
    tokio::select! {
        r = a => r??,
        r = w => r??,
    }
    Ok(())
}

/// Known agent sockets, first one present wins.
fn detect_upstream() -> Option<String> {
    let candidates = [
        "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
        "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh",
    ];
    candidates.iter().find(|c| std::path::Path::new(&config::expand(c)).exists()).map(|c| c.to_string())
}

fn launchd_plist() -> PathBuf {
    config::home().join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"))
}

fn cmd_install(path: &std::path::Path) -> Result<()> {
    Config::load(path)?;
    let exe = std::env::current_exe()?.canonicalize()?;
    let logf = config::home().join("Library/Logs/pocket-agent.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array>
    <string>{}</string><string>--config</string><string>{}</string><string>serve</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/local/bin:/Applications/Tailscale.app/Contents/MacOS:/usr/bin:/bin:/run/current-system/sw/bin</string></dict>
</dict></plist>
"#,
        exe.display(),
        path.display(),
        logf.display(),
        logf.display()
    );
    let pl = launchd_plist();
    std::fs::create_dir_all(pl.parent().unwrap())?;
    let uid = unsafe { libc::getuid() };
    let _ = std::process::Command::new("launchctl").args(["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")]).output();
    std::fs::write(&pl, plist)?;
    let out = std::process::Command::new("launchctl").args(["bootstrap", &format!("gui/{uid}"), pl.to_str().unwrap()]).output()?;
    if !out.status.success() {
        bail!("launchctl bootstrap: {}", String::from_utf8_lossy(&out.stderr));
    }
    println!("installed {}\nbinary: {}\nlog: {}", pl.display(), exe.display(), logf.display());
    Ok(())
}

fn cmd_uninstall() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let out = std::process::Command::new("launchctl").args(["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")]).output()?;
    let err = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && !err.contains("No such process") {
        bail!("launchctl bootout: {err}");
    }
    let pl = launchd_plist();
    if pl.exists() {
        std::fs::remove_file(pl)?;
    }
    println!("removed launchd agent");
    Ok(())
}

fn cmd_ssh_config(path: &std::path::Path) -> Result<()> {
    let cfg = Config::load(path)?;
    println!(
        "# In ~/.ssh/config, point every host at this agent.\n# Keys registered from the phone are signed on the phone; anything else is forwarded to the upstream agent.\nHost *\n  IdentityAgent \"{}\"\n",
        cfg.agent_socket
    );
    Ok(())
}

async fn cmd_status(path: &std::path::Path) -> Result<()> {
    let mut cfg = Config::load(path)?;
    let (ts, addr, public) = resolve(&mut cfg).await?;
    println!("tailscale node:   {} ({})", ts.dns_name, ts.ips.join(", "));
    println!("app:              {}  (bound to {addr}, tls {})", public, cfg.tls);
    println!("allowed logins:   {}", cfg.allowed_logins.join(", "));
    println!("agent socket:     {}", cfg.agent_socket);
    println!("upstream agent:   {}", if cfg.upstream_socket.is_empty() { "none" } else { &cfg.upstream_socket });
    println!("daemon:           {}", if std::path::Path::new(&cfg.agent_socket).exists() { "socket present" } else { "not running (socket missing)" });
    if let Ok(p) = AppState::load_persisted(&cfg.state_file) {
        for d in p.devices {
            println!("device:           {} ({} key(s){}, seen {})", d.name, d.keys.len(), if d.push.is_some() { ", push" } else { "" }, d.last_seen);
            for k in d.keys {
                println!("                    {} {} {}", k.key_type, k.fingerprint, k.name);
            }
        }
    }
    Ok(())
}

/// List the keys the upstream agent offers: (blob, comment).
pub async fn upstream_keys(socket: &str) -> Option<Vec<(Vec<u8>, String)>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if socket.is_empty() {
        return None;
    }
    let mut c = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::UnixStream::connect(socket)).await.ok()?.ok()?;
    c.write_all(&[0, 0, 0, 1, 11]).await.ok()?;
    let mut len = [0u8; 4];
    c.read_exact(&mut len).await.ok()?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    c.read_exact(&mut buf).await.ok()?;
    if buf.first() != Some(&12) {
        return None;
    }
    let rd = |pos: &mut usize| -> Option<Vec<u8>> {
        let n = u32::from_be_bytes(buf.get(*pos..*pos + 4)?.try_into().ok()?) as usize;
        *pos += 4;
        let s = buf.get(*pos..*pos + n)?.to_vec();
        *pos += n;
        Some(s)
    };
    let mut pos = 1;
    let n = u32::from_be_bytes(buf.get(1..5)?.try_into().ok()?);
    pos += 4;
    let mut out = vec![];
    for _ in 0..n {
        let blob = rd(&mut pos)?;
        let comment = rd(&mut pos)?;
        out.push((blob, String::from_utf8_lossy(&comment).into_owned()));
    }
    Some(out)
}
