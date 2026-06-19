# redirtor

`redirtor` is a small, single-binary SSH reverse tunnel agent. It runs on an
internal Windows host, connects to a public relay server with key-based SSH
authentication, and opens a remote (reverse) TCP port forward. Anyone who can
reach the relay can then SSH to the exposed port and be tunneled to an internal
host that is not directly reachable from the internet.

It is intended for remote maintenance scenarios where an internal machine needs
to expose a local service (typically its own SSH server, or another internal SSH
server) through a relay.

Pre-built Windows binaries are available from the
[GitHub Releases](https://github.com/acefeel/redirtor/releases) page.

## How it works

```text
+-------------+            SSH connection            +---------------+
|  redirtor   |  =================================>  |  relay server |
|  (Windows)  |   remote forward: relay:4022 ---->   |  (public)     |
+-------------+                                      +---------------+
        |                                                    |
        | forwards to internal host                          | user runs:
        v                                                    v
+-------------+                                      +---------------+
|  internal   |                                      | ssh root@relay|
|  sshd:22    |                                      | -p 4022       |
+-------------+                                      +---------------+
```

## Relay server setup

Create a dedicated, locked-down user on the relay that can only open the
reverse tunnel.

### 1. Generate a key pair for redirtor

On your build / admin machine:

```bash
mkdir -p ~/.redirtor/keys
ssh-keygen -t ed25519 -f ~/.redirtor/keys/redirtor_relay -C "redirtor@relay" -N ""
```

This creates:

- `~/.redirtor/keys/redirtor_relay` — private key (copy to the Windows host)
- `~/.redirtor/keys/redirtor_relay.pub` — public key (install on the relay)

### 2. Create the locked-down relay user

Copy `scripts/setup-relay-user.sh` to the relay and run it as root:

```bash
# on the relay
sudo ./setup-relay-user.sh "$(cat ~/.redirtor/keys/redirtor_relay.pub)"
```

The script will:

- create the system user `redirtor` with a non-login shell
- write an `authorized_keys` entry that **only** allows reverse forwarding to
  `127.0.0.1:4022` and rejects any shell/session request
- print a recommended `sshd_config` `Match` block

Add the printed `Match` block to `/etc/ssh/sshd_config` (place it **before**
any broader `Match` blocks), then reload SSH:

```bash
sudo systemctl reload sshd
```

If you need a different port, set `LISTEN_PORT` before running the script:

```bash
sudo LISTEN_PORT=4023 ./setup-relay-user.sh "$(cat ~/.redirtor/keys/redirtor_relay.pub)"
```

## Command line

```text
redirtor.exe -S <USER@HOST> -Sp <SSH_PORT> -p <REMOTE_PORT> -D <DEST_HOST> -Dp <DEST_PORT> [OPTIONS]
```

### Required arguments

| Short | Long               | Description                                                      |
|-------|--------------------|------------------------------------------------------------------|
| `-S`  | `--server`         | Relay server as `user@host`, e.g. `redir@myserver.example.com`   |
| `-Sp` | `--server-port`    | Relay server SSH port (default: `22`)                            |
| `-p`  | `--remote-port`    | Port to open on the relay (bound to the relay's loopback)        |
| `-R`  | `--remote-bind`    | Address on the relay to bind the remote port to (default: `127.0.0.1`) |
| `-D`  | `--destination`    | Internal host to forward incoming connections to                 |
| `-Dp` | `--destination-port` | Port on the internal host (default: `22`)                       |
| `-k`  | `--key`            | Path to the SSH private key used to authenticate to the relay    |

### Optional arguments

| Long                 | Description                                                           |
|----------------------|-----------------------------------------------------------------------|
| `--key-passphrase`   | Passphrase for the private key                                        |
| `--known-hosts`      | Path to the known-hosts file (default: `~/.ssh/known_hosts`)          |
| `--accept-host-key`  | Trust and store an unknown relay host key on first connection         |
| `--keepalive`        | Keepalive interval in seconds (default: `30`)                         |
| `--reconnect-delay`  | Seconds before reconnecting after a disconnect (default: `5`)         |
| `-v`, `--verbose`    | Enable DEBUG level logging                                            |
| `--install`          | Install as a Windows service (Windows only)                           |
| `--uninstall`        | Uninstall the Windows service (Windows only)                          |
| `--service-name`     | Windows service name, default `redirtor`                              |
| `--service-display-name` | Windows service display name                                      |
| `--service-description`  | Windows service description                                       |
| `-h`, `--help`       | Show full help                                                        |

### Example

Expose the relay's local port `4022` and forward it to the internal host
`10.0.0.5:22`:

```powershell
redirtor.exe -S redir@myserver -Sp 22 -p 4022 -D 10.0.0.5 -Dp 22 -k C:\Users\redir\.ssh\id_ed25519 --accept-host-key
```

On the relay, connect through the tunnel:

```bash
ssh root@localhost -p 4022
```

To reach the Windows host where `redirtor` is running, set `-D 127.0.0.1` and
`-Dp 22` (or the port your local SSH server listens on).

## Running as a Windows service

On Windows you can install `redirtor` as a system service so it starts
automatically and runs without a logged-in user.

Install a service (run PowerShell as Administrator):

```powershell
redirtor.exe `
  --install `
  --service-name redirtor-server1 `
  --service-display-name "Redirtor to server1" `
  -S redirtor@relay.example.com -Sp 22 `
  -p 4022 -D 10.0.0.5 -Dp 22 `
  -k C:\redirtor\keys\redirtor_relay
```

The installer stores the tunnel parameters in the service command line. The
private key file is read once at install time, encrypted with Windows DPAPI
(machine scope), and stored under the service registry key. After a successful
install the original `-k` key file can be removed from the host; the service
does not need it at startup.

You can install multiple services pointing at different relays or destinations:

```powershell
redirtor.exe `
  --install `
  --service-name redirtor-server2 `
  --service-display-name "Redirtor to server2" `
  -S redirtor@other.example.com -Sp 22 `
  -p 4023 -D 10.0.0.6 -Dp 22 `
  -k C:\redirtor\keys\other_relay
```

Start / stop the service with the normal Windows tools:

```powershell
Start-Service -Name redirtor-server1
Stop-Service -Name redirtor-server1
```

Or:

```cmd
sc start redirtor-server1
sc stop redirtor-server1
```

Uninstall a service (Administrator):

```powershell
redirtor.exe --uninstall --service-name redirtor-server1
```

## Security notes

- **Do not run with `--accept-host-key` permanently.** Use it only once to pin
  the relay's host key, then remove it for subsequent runs.
- The remote forward is bound to the relay's loopback address by default, so it
  is only reachable from the relay itself. If you want other hosts to reach it,
  you can change `-R`, but make sure you understand the access implications.
- When installed as a Windows service, the private key is encrypted with
  Windows DPAPI and stored under the service's registry key. The original key
  file can be removed after installation; uninstalling the service removes the
  stored key.
- Protect the private key file with appropriate filesystem permissions. The key
  passphrase, if provided on the command line, may be visible in process lists.

## Publishing & repository hygiene

This repository is intended to be public. **Never commit SSH private keys, relay
passwords, or internal host names.** The `.gitignore` already excludes common
private-key filenames (`redirtor_relay`, `*_relay`, `*.key`) and compiled
binaries.

- Keep key files in a secure location such as `~/.redirtor/keys/` or a password
  manager.
- When installing as a Windows service, the private key is encrypted with
  DPAPI and stored in the registry; the original file can be removed.
- GitHub Actions builds Windows release binaries automatically on tagged
  releases (`v*`).

## Building from source

### Native build (current platform)

```bash
cargo build --release
```

The binary is placed in `target/release/redirtor` (or `redirtor.exe` on
Windows).

### Cross-compile for Windows from macOS/Linux

The easiest way is to use the GNU Windows target with a MinGW toolchain.

1. Install the target:

   ```bash
   rustup target add x86_64-pc-windows-gnu
   ```

2. Install a MinGW cross compiler. On macOS with Homebrew:

   ```bash
   brew install mingw-w64
   ```

3. Install NASM. The cryptography backend (`aws-lc-rs`) needs it for the
   Windows assembly files:

   ```bash
   brew install nasm
   ```

4. Build:

   ```bash
   cargo build --release --target x86_64-pc-windows-gnu
   ```

The resulting executable is at `target/x86_64-pc-windows-gnu/release/redirtor.exe`.

### Cross-compile for Windows from Windows

On Windows, install the MSVC target and Visual Studio Build Tools, then:

```powershell
cargo build --release --target x86_64-pc-windows-msvc
```

## Dependencies

- [russh](https://crates.io/crates/russh) — pure-Rust async SSH client library
- [tokio](https://crates.io/crates/tokio) — async runtime
- [clap](https://crates.io/crates/clap) — command-line parsing
- [anyhow](https://crates.io/crates/anyhow) / [tracing](https://crates.io/crates/tracing) — error handling and logging

## License

MIT
