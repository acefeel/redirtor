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

On the relay, as root:

```bash
# create a non-login user
useradd --system --create-home --shell /usr/sbin/nologin --comment "redirtor tunnel" redirtor

# write the public key with strict forwarding restrictions
mkdir -p /home/redirtor/.ssh
chmod 700 /home/redirtor/.ssh
cat > /home/redirtor/.ssh/authorized_keys <<'EOF'
restrict,permitlisten="127.0.0.1:4022",command="/bin/false" PASTE_PUBLIC_KEY_HERE
EOF
chmod 600 /home/redirtor/.ssh/authorized_keys
chown -R redirtor:redirtor /home/redirtor
```

Replace `PASTE_PUBLIC_KEY_HERE` with the contents of `~/.redirtor/keys/redirtor_relay.pub`.

Add this `Match` block to `/etc/ssh/sshd_config` (before any broader `Match`
blocks):

```text
Match User redirtor
    AllowTcpForwarding remote
    GatewayPorts no
    ForceCommand /bin/false
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
```

Then reload sshd:

```bash
sudo systemctl reload sshd
```

## Command line

```text
redirtor.exe -S <USER@HOST> -Sp <SSH_PORT> -p <REMOTE_PORT> -D <DEST_HOST> -Dp <DEST_PORT> -k <KEY_FILE> [OPTIONS]
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

## Running unattended

`redirtor` is a console application. The easiest way to run it as a Windows
service is with [nssm](https://nssm.cc/) (the Non-Sucking Service Manager).

### Example with nssm

1. Download `nssm.exe` and place it in a directory on your `PATH`, e.g.
   `C:\Windows\System32`.

2. Install `redirtor` as a service:

   ```powershell
   nssm install redirtor C:\redirtor\redirtor.exe
   ```

   In the nssm GUI, set the **Arguments** to:

   ```text
   -S redirtor@59.110.69.114 -Sp 22 -p 4022 -D 192.168.0.51 -Dp 22 -k C:\redirtor\redirtor_relay
   ```

   Or install directly from the command line:

   ```powershell
   nssm install redirtor C:\redirtor\redirtor.exe "-S redirtor@59.110.69.114 -Sp 22 -p 4022 -D 192.168.0.51 -Dp 22 -k C:\redirtor\redirtor_relay"
   nssm set redirtor DisplayName "redirtor tunnel"
   nssm set redirtor Start SERVICE_AUTO_START
   ```

3. Start the service:

   ```powershell
   nssm start redirtor
   ```

4. View logs (nssm captures stdout/stderr by default):

   ```powershell
   nssm edit redirtor
   ```

Other alternatives include Windows Task Scheduler, AlwaysUp, or FireDaemon.
Keep the private key file in a secure location and restrict its ACLs.

## Security notes

- **Do not run with `--accept-host-key` permanently.** Use it only once to pin
  the relay's host key, then remove it for subsequent runs.
- The remote forward is bound to the relay's loopback address by default, so it
  is only reachable from the relay itself. If you want other hosts to reach it,
  you can change `-R`, but make sure you understand the access implications.
- Protect the private key file with appropriate filesystem permissions. The key
  passphrase, if provided on the command line, may be visible in process lists.

## Publishing & repository hygiene

This repository is intended to be public. **Never commit SSH private keys, relay
passwords, or internal host names.** The `.gitignore` already excludes common
private-key filenames (`redirtor_relay`, `*_relay`, `*.key`) and compiled
binaries.

- Keep key files in a secure location such as `~/.redirtor/keys/` or a password
  manager.
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
