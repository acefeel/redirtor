use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tracing::{error, info};
use windows_dpapi::{decrypt_data, encrypt_data, Scope};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use winreg::enums::*;
use winreg::RegKey;

use crate::Args;
use crate::ConfigInternal;

static SERVICE_CONFIG: std::sync::OnceLock<ConfigInternal> = std::sync::OnceLock::new();

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

pub fn install(args: &Args, raw_args: Vec<String>) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&std::ffi::OsStr>,
        ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("failed to open Service Control Manager")?;

    let service_name = args.service_name.clone();
    let display_name = args
        .service_display_name
        .clone()
        .unwrap_or_else(|| service_name.clone());
    let description = args
        .service_description
        .clone()
        .unwrap_or_else(|| "redirtor SSH reverse tunnel agent".to_string());

    let exe = env::current_exe().context("failed to get current executable path")?;
    let exe_str = exe.to_string_lossy();

    let service_args = build_service_args(raw_args);
    let binary_path = if exe_str.chars().any(|c| c == ' ' || c == '\t') {
        format!("\"{}\" {}", exe_str, service_args.join(" "))
    } else {
        format!("{} {}", exe_str, service_args.join(" "))
    };

    let service_info = ServiceInfo {
        name: OsString::from(&service_name),
        display_name: OsString::from(display_name),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(binary_path),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(
            &service_info,
            ServiceAccess::START | ServiceAccess::CHANGE_CONFIG,
        )
        .with_context(|| format!("failed to create service '{}'", service_name))?;

    if let Err(e) = service.set_description(&description) {
        info!("could not set service description: {}", e);
    }

    if let Some(key_path) = &args.key {
        store_encrypted_key(&service_name, key_path)
            .with_context(|| format!("failed to store encrypted key for service '{}'", service_name))?;
        info!("encrypted private key stored for service '{}'", service_name);
    }

    info!("service '{}' installed successfully", service_name);
    info!("binary path: {}", service_info.executable_path.display());
    Ok(())
}

pub fn uninstall(service_name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&std::ffi::OsStr>,
        ServiceManagerAccess::CONNECT,
    )
    .context("failed to open Service Control Manager")?;
    let service = manager
        .open_service(OsString::from(service_name), ServiceAccess::DELETE)
        .with_context(|| format!("failed to open service '{}'", service_name))?;
    service
        .delete()
        .with_context(|| format!("failed to delete service '{}'", service_name))?;

    if let Err(e) = delete_encrypted_key(service_name) {
        info!("could not delete stored key for service '{}': {}", service_name, e);
    } else {
        info!("stored key for service '{}' removed", service_name);
    }

    info!("service '{}' uninstalled", service_name);
    Ok(())
}

pub fn run(config: ConfigInternal) -> Result<()> {
    SERVICE_CONFIG
        .set(config)
        .map_err(|_| anyhow::anyhow!("service config already set"))?;

    let service_name = SERVICE_CONFIG
        .get()
        .context("service config missing")?
        .service_name
        .clone();

    windows_service::service_dispatcher::start(service_name, ffi_service_main)
        .context("service dispatcher failed")
}

define_windows_service!(ffi_service_main, service_main);

pub fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("service error: {:#}", e);
    }
}

fn run_service() -> Result<()> {
    let config = SERVICE_CONFIG
        .get()
        .context("service config not initialized")?
        .clone();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown.clone()));

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                if let Some(sd) = shutdown_tx.lock().unwrap().take() {
                    sd.store(true, Ordering::Relaxed);
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(&config.service_name, event_handler)
        .context("failed to register service control handler")?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
        .context("failed to set StartPending status")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .context("failed to set Running status")?;

    runtime.block_on(async {
        if let Err(e) = crate::run(config, shutdown).await {
            error!("tunnel error: {:#}", e);
        }
    });

    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .context("failed to set Stopped status")?;

    Ok(())
}

fn build_service_args(raw_args: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for (i, arg) in raw_args.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        match arg.as_str() {
            "--install" | "--uninstall" | "--service" => {
                // skip these; they are only relevant for the installer process
            }
            "--service-display-name" | "--service-description" | "--key-data" => {
                skip_next = true;
            }
            "-k" | "--key" => {
                // The key file is read and encrypted into the registry at
                // install time; the service itself does not reference it.
                skip_next = true;
            }
            _ => out.push(arg.clone()),
        }
    }
    out.push("--service".to_string());
    out
}

fn parameters_key_path(service_name: &str) -> String {
    format!(
        "SYSTEM\\CurrentControlSet\\Services\\{}\\Parameters",
        service_name
    )
}

pub fn store_encrypted_key(service_name: &str, key_path: &Path) -> Result<()> {
    let secret = std::fs::read_to_string(key_path)
        .with_context(|| format!("failed to read key file {}", key_path.display()))?;
    let encrypted = encrypt_data(secret.as_bytes(), Scope::Machine, None)
        .context("DPAPI encryption failed")?;
    let encoded = BASE64.encode(&encrypted);

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _disp) = hklm
        .create_subkey(&parameters_key_path(service_name))
        .context("failed to create service Parameters registry key")?;
    key.set_value("EncryptedKey", &encoded)
        .context("failed to write EncryptedKey registry value")?;
    Ok(())
}

pub fn load_encrypted_key(service_name: &str) -> Result<Option<String>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey(&parameters_key_path(service_name)) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("failed to open service Parameters registry key"),
    };
    let encoded: String = key
        .get_value("EncryptedKey")
        .context("failed to read EncryptedKey registry value")?;
    let encrypted = BASE64
        .decode(&encoded)
        .context("failed to base64-decode stored key")?;
    let decrypted = decrypt_data(&encrypted, Scope::Machine, None)
        .context("DPAPI decryption failed")?;
    let secret = String::from_utf8(decrypted).context("decrypted key is not valid UTF-8")?;
    Ok(Some(secret))
}

fn delete_encrypted_key(service_name: &str) -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = parameters_key_path(service_name);
    hklm.delete_subkey_all(&path)
        .context("failed to delete service Parameters registry key")?;
    Ok(())
}

