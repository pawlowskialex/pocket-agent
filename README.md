# pocket-agent

An SSH agent for macOS that keeps the private keys on your phone.

The agent runs on the Mac and speaks the usual SSH agent protocol. When a client asks it to
sign with one of the phone's keys, the request is sent to a small web app on the phone over
your Tailscale network. You tap Sign, the phone signs with WebCrypto, and the signature goes
back to the Mac. The private key never leaves the phone.

Keys the phone does not have can be forwarded to another agent on the Mac (1Password,
Secretive, ssh-agent) so local use keeps working as before.

## Why

Desktop agents like 1Password's show an approval dialog on the Mac's screen. That is useless
when you are logged into the Mac remotely. Copying the key onto the Mac defeats the point of
a hardware or vault-backed key. Keeping the key on the phone and approving each signature
there works from any kind of session, and there is no unlock or session to expire.

## How it works

```
git / ssh -> ~/.pocket-agent/agent.sock -> pocket-agent
                                             |
                       key registered by the phone?
                       no  -> upstream agent (optional)
                       yes -> pending request; Web Push to the phone; phone polls, signs, replies
```

On the phone:

- Import a key once by pasting it (OpenSSH, PKCS#8 or traditional PEM; Ed25519, ECDSA, RSA).
  The key is parsed in the browser and imported into WebCrypto as a non-extractable key, then
  stored in IndexedDB. JavaScript can sign with it but cannot read it back. Only the public
  key is sent to the Mac.
- Each signing request shows the key, the login user, and the process chain on the Mac that
  asked. Tap Sign or Deny. Per key you can enable automatic signing while the app is open.
- Add the app to the Home Screen and enable notifications to get a push when a signature is
  needed. Push requires HTTPS, which the agent serves with a Tailscale certificate.

On the Mac:

- Registered keys appear in `ssh-add -l` with the names given on the phone.
- Access to the web app is limited to devices on your tailnet logged in as you, checked with
  `tailscale whois`. Optionally restrict it to named devices. Connections from the Mac itself
  are refused.
- Requests time out after `sign_timeout_seconds` (default 120) and the client sees an agent
  failure.
- The certificate is obtained with `tailscale cert` and renewed daily. A VAPID key pair for Web
  Push is generated on first run. Registered public keys, push subscriptions and the VAPID keys
  are kept in `~/.pocket-agent/state.json`.

## Requirements

- macOS with Tailscale installed, MagicDNS on, and HTTPS certificates enabled for the tailnet
  (admin console, DNS page).
- A phone on the same tailnet. Push notifications need iOS 16.4 or later with the app added to
  the Home Screen, or Android.

## Install

With Nix (nix-darwin):

```nix
inputs.pocket-agent = {
  url = "github:pawlowskialex/pocket-agent";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

Add `inputs.pocket-agent.darwinModules.default` to your modules and enable the service:

```nix
services.pocket-agent = {
  enable = true;
  settings = {
    upstream_socket = "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"; # optional
    # allowed_nodes = [ "my-phone" ];   # optional, names as in `tailscale status`
  };
};
```

The module runs the agent as a launchd user agent and exports `POCKET_AGENT_CONFIG` so the
CLI finds the same config.

Without Nix:

```sh
cargo build --release
./target/release/pocket-agent init       # config from your tailnet, fetches the certificate
./target/release/pocket-agent install    # launchd agent; log in ~/Library/Logs/pocket-agent.log
```

## Setup

Point ssh at the agent in `~/.ssh/config`:

```
Host *
  IdentityAgent "~/.pocket-agent/agent.sock"
```

or with home-manager:

```nix
programs.ssh.settings."*".IdentityAgent = "~/.pocket-agent/agent.sock";
```

Then run `pocket-agent status`, open the app URL on the phone, import a key, add the app to the
Home Screen and enable notifications.

## Configuration

`~/.config/pocket-agent/config.json`, written by `init`:

| key | meaning |
|---|---|
| `agent_socket` | socket the agent listens on |
| `upstream_socket` | another agent's socket to forward unknown keys to; empty disables forwarding |
| `state_file` | registered public keys, push subscriptions, VAPID keys |
| `http_bind`, `http_port` | where the app listens; empty bind means the Mac's Tailscale IPv4 |
| `public_url` | URL used by the phone; default `https://<magicdns-name>:<port>` |
| `tls`, `tls_cert`, `tls_key`, `tls_auto` | HTTPS with a Tailscale certificate, fetched and renewed automatically |
| `allowed_logins` | tailnet logins allowed to use the app; default: yours |
| `allowed_nodes` | optional list of tailnet device names |
| `allow_local_api` | for tests only; lets loopback use the app |
| `sign_timeout_seconds` | how long a request waits for the phone |
| `push_contact` | contact put into VAPID tokens; default `mailto:<your tailnet login>` |

Commands: `init`, `serve`, `cert`, `install`, `uninstall`, `ssh-config`, `status`.

## Security notes

- Private keys exist only in the phone browser's storage, as non-extractable WebCrypto keys.
  Clearing the site data or removing the app deletes them.
- Anyone with a shell on the Mac as you can request a signature. Each request is shown on the
  phone with the requesting process chain, and nothing is signed until you tap Sign, unless
  you enabled automatic signing for that key.
- The Mac stores public keys only. No endpoint returns private key material.
- Push payloads are encrypted (RFC 8291) and contain the key name, the login user and the
  ssh or git command line. The push service sees ciphertext.
- `ssh-add -d` and `ssh-add -D` are forwarded to the upstream agent; they do not affect keys on
  the phone. Remove those in the app.

## Tests

```sh
node test/sshkey.test.mjs   # browser-side parser and signer against ssh-keygen output
bash test/e2e.sh            # agent, a headless Node "phone", and a throwaway ssh-agent upstream
```

## License

MIT
