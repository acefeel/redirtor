use anyhow::{bail, Context, Result};
use clap::Parser;
use russh::client::{Config, DisconnectReason, Handler, Msg, Session};
use russh::keys::{
    check_known_hosts_path, load_secret_key, PrivateKeyWithHashAlg, PublicKey,
};
use russh::keys::known_hosts::learn_known_hosts_path;
use russh::Channel;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "redirtor",
    version,
    about = "SSH reverse tunnel agent for remote maintenance"
)]
struct Args {
    /// Relay server in user@host or user@host:port format
    #[arg(short = 'S', long, value_name = "USER@HOST[:PORT]")]
    server: String,

    /// Relay server SSH port
    #[arg(long, visible_alias = "sp", value_name = "PORT", default_value = "22")]
    server_port: u16,

    /// Port to listen on the relay server (localhost side)
    #[arg(short = 'p', long, value_name = "PORT")]
    remote_port: u16,

    /// Bind address on the relay server
    #[arg(short = 'R', long, value_name = "ADDR", default_value = "127.0.0.1")]
    remote_bind: String,

    /// Internal destination host to forward connections to
    #[arg(short = 'D', long, value_name = "HOST")]
    destination: String,

    /// Internal destination port
    #[arg(long, visible_alias = "dp", value_name = "PORT", default_value = "22")]
    destination_port: u16,

    /// SSH private key file path
    #[arg(short = 'k', long, value_name = "PATH")]
    key: PathBuf,

    /// Passphrase for the SSH private key
    #[arg(long, value_name = "PASS")]
    key_passphrase: Option<String>,

    /// Known hosts file path
    #[arg(long, value_name = "PATH")]
    known_hosts: Option<PathBuf>,

    /// Automatically accept and save unknown host keys
    #[arg(long)]
    accept_host_key: bool,

    /// SSH keepalive interval in seconds
    #[arg(long, value_name = "SECS", default_value = "30")]
    keepalive: u64,

    /// Delay before reconnecting after a disconnect
    #[arg(long, value_name = "SECS", default_value = "5")]
    reconnect_delay: u64,

    /// Enable verbose (DEBUG) logging
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
struct ConfigInternal {
    server_user: String,
    server_host: String,
    server_port: u16,
    remote_port: u16,
    remote_bind: String,
    destination: String,
    destination_port: u16,
    key: PathBuf,
    key_passphrase: Option<String>,
    known_hosts: PathBuf,
    accept_host_key: bool,
    keepalive: u64,
    reconnect_delay: u64,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("fatal error: {:#}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let raw_args: Vec<String> = env::args().collect();
    let processed = preprocess_args(raw_args);
    let args = Args::parse_from(processed);

    setup_logging(args.verbose);

    let (server_user, server_host, server_port) = parse_user_host(&args.server, args.server_port)?;
    let known_hosts = args
        .known_hosts
        .clone()
        .unwrap_or_else(default_known_hosts_path);

    let config = ConfigInternal {
        server_user,
        server_host,
        server_port,
        remote_port: args.remote_port,
        remote_bind: args.remote_bind,
        destination: args.destination,
        destination_port: args.destination_port,
        key: args.key,
        key_passphrase: args.key_passphrase,
        known_hosts,
        accept_host_key: args.accept_host_key,
        keepalive: args.keepalive,
        reconnect_delay: args.reconnect_delay,
    };

    info!(
        "redirtor started: {}@{}:{} -> [{}]:{} -> {}:{}",
        config.server_user,
        config.server_host,
        config.server_port,
        config.remote_bind,
        config.remote_port,
        config.destination,
        config.destination_port
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c received, shutting down");
            Ok(())
        }
        res = run_loop(config) => res,
    }
}

async fn run_loop(config: ConfigInternal) -> Result<()> {
    loop {
        if let Err(e) = run_once(&config).await {
            error!("tunnel error: {:#}", e);
        } else {
            info!("tunnel closed");
        }
        info!("reconnecting in {} seconds", config.reconnect_delay);
        sleep(Duration::from_secs(config.reconnect_delay)).await;
    }
}

fn parse_user_host(s: &str, default_port: u16) -> Result<(String, String, u16)> {
    let (user, host_part) = s.split_once('@').with_context(|| {
        format!(
            "server must be in user@host format, e.g. redir@192.168.1.1 or redir@relay.example.com:2222"
        )
    })?;

    if user.is_empty() || host_part.is_empty() {
        bail!("server user and host must not be empty");
    }

    // Bracketed IPv6 with optional port: [::1] or [::1]:2222
    if let Some(inner) = host_part.strip_prefix('[') {
        let (addr, port) = if let Some((a, p)) = inner.rsplit_once("]:") {
            (a, Some(p))
        } else if let Some(a) = inner.strip_suffix(']') {
            (a, None)
        } else {
            bail!("invalid IPv6 address in server string: missing closing bracket");
        };
        let port = parse_optional_port(port, default_port)?;
        return Ok((user.to_string(), format!("[{}]", addr), port));
    }

    // Hostname or IPv4, optionally with `:port`.
    // The last colon separates host from port, but IPv4 addresses also contain
    // colons. We therefore only treat the trailing segment as a port if it is
    // all digits and the host part is not a bare IPv4 address with a port.
    if let Some((host, port_str)) = host_part.rsplit_once(':') {
        if !host.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            let port = parse_optional_port(Some(port_str), default_port)?;
            return Ok((user.to_string(), host.to_string(), port));
        }
    }

    Ok((user.to_string(), host_part.to_string(), default_port))
}

fn parse_optional_port(port: Option<&str>, default_port: u16) -> Result<u16> {
    match port {
        None => Ok(default_port),
        Some(p) => p
            .parse::<u16>()
            .with_context(|| format!("invalid port number '{}'", p)),
    }
}

fn preprocess_args(args: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        match arg.as_str() {
            "-Sp" => out.push("--server-port".to_string()),
            "-Dp" => out.push("--destination-port".to_string()),
            _ => out.push(arg),
        }
    }
    out
}

fn setup_logging(verbose: bool) {
    let filter = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .with_thread_ids(false)
        .init();
}

fn default_known_hosts_path() -> PathBuf {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".ssh").join("known_hosts")
}

async fn run_once(config: &ConfigInternal) -> Result<()> {
    let key = load_secret_key(&config.key, config.key_passphrase.as_deref())
        .with_context(|| format!("failed to load private key {}", config.key.display()))?;

    let handler = RedirtorHandler {
        config: config.clone(),
    };

    let ssh_config = Arc::new(Config::default());
    let addr_str = format!("{}:{}", config.server_host, config.server_port);
    let addr: SocketAddr = addr_str
        .parse()
        .with_context(|| format!("invalid relay server address '{}'", addr_str))?;

    info!("connecting to {}", addr);
    let mut handle = russh::client::connect(ssh_config, addr, handler).await?;

    let hash_alg = if key.algorithm().is_rsa() {
        handle.best_supported_rsa_hash().await?.flatten()
    } else {
        None
    };
    let auth_res = handle
        .authenticate_publickey(
            &config.server_user,
            PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
        )
        .await?;
    if !auth_res.success() {
        bail!("SSH authentication failed: {:?}", auth_res);
    }
    info!("authenticated as {}", config.server_user);

    handle
        .tcpip_forward(&config.remote_bind, config.remote_port.into())
        .await?;
    info!(
        "remote forward registered: {}:{} -> {}:{}",
        config.remote_bind,
        config.remote_port,
        config.destination,
        config.destination_port
    );

    // Keep the session alive with periodic keepalives.
    loop {
        sleep(Duration::from_secs(config.keepalive)).await;
        if handle.is_closed() {
            info!("SSH session closed");
            break;
        }
        if let Err(e) = handle.send_keepalive(true).await {
            error!("keepalive failed: {}", e);
            break;
        }
        debug!("keepalive ok");
    }

    Ok(())
}

struct RedirtorHandler {
    config: ConfigInternal,
}

impl Handler for RedirtorHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let host = &self.config.server_host;
        let port = self.config.server_port;

        match check_known_hosts_path(
            host,
            port,
            server_public_key,
            &self.config.known_hosts,
        ) {
            Ok(true) => {
                info!("host key verified for {}:{}", host, port);
                return Ok(true);
            }
            Ok(false) => {
                if self.config.accept_host_key {
                    info!("accepting new host key for {}:{}", host, port);
                    learn_known_hosts_path(
                        host,
                        port,
                        server_public_key,
                        &self.config.known_hosts,
                    )?;
                    return Ok(true);
                } else {
                    error!(
                        "host key not found for {}:{}. Use --accept-host-key to trust it.",
                        host, port
                    );
                    return Ok(false);
                }
            }
            Err(e) => {
                error!("known_hosts check failed: {}", e);
                return Ok(false);
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(
            "new forwarded connection from {}:{} to {}:{}",
            originator_address, originator_port, connected_address, connected_port
        );
        let dest = format!("{}:{}", self.config.destination, self.config.destination_port);
        tokio::spawn(async move {
            if let Err(e) = forward_channel(channel, dest).await {
                error!("forward error: {}", e);
            }
        });
        Ok(())
    }

    async fn disconnected(
        &mut self,
        _reason: DisconnectReason<anyhow::Error>,
    ) -> Result<(), Self::Error> {
        info!("disconnected from relay");
        Ok(())
    }
}

async fn forward_channel(channel: Channel<Msg>, dest: String) -> Result<()> {
    let stream = channel.into_stream();
    let tcp = TcpStream::connect(&dest).await?;
    let (mut chan_read, mut chan_write) = tokio::io::split(stream);
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);

    let upstream = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut chan_read, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
    });
    let downstream = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut tcp_read, &mut chan_write).await;
        let _ = chan_write.shutdown().await;
    });

    let _ = tokio::join!(upstream, downstream);
    info!("forward to {} closed", dest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_host_basic() {
        let (user, host, port) = parse_user_host("redir@192.168.1.1", 22).unwrap();
        assert_eq!(user, "redir");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_user_host_with_port() {
        let (user, host, port) = parse_user_host("redir@relay.example.com:2222", 22).unwrap();
        assert_eq!(user, "redir");
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 2222);
    }

    #[test]
    fn parse_user_host_ipv6() {
        let (user, host, port) = parse_user_host("redir@[::1]:2222", 22).unwrap();
        assert_eq!(user, "redir");
        assert_eq!(host, "[::1]");
        assert_eq!(port, 2222);
    }

    #[test]
    fn parse_user_host_ipv6_no_port() {
        let (user, host, port) = parse_user_host("redir@[::1]", 22).unwrap();
        assert_eq!(user, "redir");
        assert_eq!(host, "[::1]");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_user_host_invalid_port() {
        assert!(parse_user_host("redir@host:99999", 22).is_err());
    }

    #[test]
    fn parse_user_host_missing_at() {
        assert!(parse_user_host("justhost", 22).is_err());
    }
}
