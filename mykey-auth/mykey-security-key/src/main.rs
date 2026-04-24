#[path = "auth_client.rs"]
mod auth_client;
#[path = "daemon_client.rs"]
mod daemon_client;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const AUTH_ROOT: &str = "/etc/mykey/auth";
const REGISTRY_FILENAME: &str = "security-keys.registry.sealed";
const PAM_U2F_AUTHFILE: &str = "/etc/mykey/security-keys.pam_u2f";
const PAM_U2F_ORIGIN: &str = "pam://mykey";
const PAM_U2F_APPID: &str = "pam://mykey";
const ELEVATED_AUTH_HELPER_CANDIDATES: &[&str] = &[
    "/usr/local/bin/mykey-elevated-auth",
    "/usr/bin/mykey-elevated-auth",
];
const PAM_U2F_CFG_CANDIDATES: &[&str] = &["/usr/bin/pamu2fcfg", "/usr/local/bin/pamu2fcfg"];
const PAM_U2F_MODULE_CANDIDATES: &[&str] = &[
    "/usr/lib/security/pam_u2f.so",
    "/usr/lib64/security/pam_u2f.so",
];
const PAM_SECURITY_KEY_SERVICE_CANDIDATES: &[&str] = &["/etc/pam.d/mykey-security-key-auth"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandKind {
    Enroll { nickname: Option<String> },
    Status,
    Unenroll,
    Test,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SecurityKeyRegistry {
    version: u32,
    #[serde(default)]
    account_name: String,
    #[serde(default)]
    keys: Vec<SecurityKeyEnrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityKeyEnrollment {
    mykey_id: String,
    nickname: Option<String>,
    provider: SecurityKeyProvider,
    enrolled_at_unix: u64,
    enrolled_at_utc: String,
    credential_hint: String,
    device_label: Option<String>,
    touch_required: bool,
    key_pin_required: bool,
    mapping_fingerprint: String,
    pam_u2f_mapping: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SecurityKeyProvider {
    PamU2f,
}

impl SecurityKeyProvider {
    fn as_str(self) -> &'static str {
        match self {
            Self::PamU2f => "pam_u2f",
        }
    }
}

impl SecurityKeyRegistry {
    fn normalised(mut self, system_username: &str) -> Self {
        if self.version == 0 {
            self.version = 1;
        }
        if self.account_name.trim().is_empty() {
            self.account_name = system_username.to_string();
        }
        self.keys
            .retain(|entry| !entry.mykey_id.trim().is_empty() && !entry.pam_u2f_mapping.is_empty());
        self.keys.sort_by_key(|entry| entry.enrolled_at_unix);
        self
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let command = parse_args(&args).unwrap_or_else(|msg| {
        eprintln!("{msg}");
        print_usage();
        std::process::exit(2);
    });

    match command {
        CommandKind::Enroll { nickname } => {
            if let Err(e) = run_enroll(nickname).await {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        CommandKind::Status => {
            if let Err(e) = run_status().await {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        CommandKind::Unenroll => {
            if let Err(e) = run_unenroll().await {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        CommandKind::Test => {
            if let Err(e) = run_test() {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}

fn parse_args(args: &[String]) -> Result<CommandKind, String> {
    match args.get(1).map(|value| value.as_str()) {
        Some("enroll") => {
            let mut nickname = None;
            let mut idx = 2;
            while idx < args.len() {
                match args[idx].as_str() {
                    "--nickname" => {
                        let value = args
                            .get(idx + 1)
                            .ok_or_else(|| "Missing value for --nickname.".to_string())?;
                        nickname = Some(value.trim().to_string()).filter(|value| !value.is_empty());
                        idx += 2;
                    }
                    other => return Err(format!("Unknown argument: {other}")),
                }
            }
            Ok(CommandKind::Enroll { nickname })
        }
        Some("status") if args.len() == 2 => Ok(CommandKind::Status),
        Some("unenroll") if args.len() == 2 => Ok(CommandKind::Unenroll),
        Some("test") if args.len() == 2 => Ok(CommandKind::Test),
        Some(other) => Err(format!("Unknown or malformed command: {other}")),
        None => Err("Missing command.".to_string()),
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  sudo mykey-security-key enroll [--nickname <name>]");
    eprintln!("  sudo mykey-security-key status");
    eprintln!("  sudo mykey-security-key unenroll");
    eprintln!("  mykey-security-key test");
}

async fn run_enroll(nickname: Option<String>) -> Result<(), String> {
    ensure_root("enroll");
    ensure_security_key_backend_for_enrollment()?;

    let target_uid = preferred_target_uid();
    let system_username = preferred_target_username()
        .ok_or_else(|| "Could not resolve the target Linux account.".to_string())?;

    let client = daemon_client::DaemonClient::connect().await?;
    if let Err(e) = ensure_pin_prerequisite(&client, target_uid).await {
        client.disconnect().await;
        return Err(e);
    }

    require_elevated_password(
        target_uid,
        "security_key_manage",
        "Security-key enrollment requires verifying your Linux account password.",
    )?;

    let mut registry = load_registry(&client, target_uid, &system_username).await?;
    println!("Touch the security key now to enroll it with MyKey.");
    let mapping = enroll_with_pamu2fcfg(&system_username)?;
    let mapping_fingerprint = mapping_fingerprint(&mapping);
    if registry
        .keys
        .iter()
        .any(|entry| entry.mapping_fingerprint == mapping_fingerprint)
    {
        client.disconnect().await;
        return Err("This security key is already enrolled in MyKey.".to_string());
    }

    let nickname = match nickname {
        Some(value) => Some(value),
        None => prompt_optional("Nickname for this key (optional): ")?,
    };
    let now = now_recorded_at();
    let credential_hint = credential_hint_from_mapping(&mapping);
    let enrollment = SecurityKeyEnrollment {
        mykey_id: format!(
            "security-key-{}",
            &mapping_fingerprint[..12.min(mapping_fingerprint.len())]
        ),
        nickname,
        provider: SecurityKeyProvider::PamU2f,
        enrolled_at_unix: now.0,
        enrolled_at_utc: now.1,
        credential_hint: credential_hint.clone(),
        device_label: None,
        touch_required: true,
        key_pin_required: false,
        mapping_fingerprint,
        pam_u2f_mapping: mapping,
    };

    registry.keys.push(enrollment.clone());
    registry = registry.normalised(&system_username);
    persist_registry(&client, target_uid, &system_username, &registry).await?;
    client.enable_security_key_auth(target_uid).await?;
    client.disconnect().await;

    println!("Enrolled security key for '{}'.", system_username);
    println!("  id: {}", enrollment.mykey_id);
    println!(
        "  nickname: {}",
        enrollment.nickname.as_deref().unwrap_or("(none)")
    );
    println!("  enrolled: {}", enrollment.enrolled_at_utc);
    println!("  credential: {}", credential_hint);
    println!("  backend: {}", enrollment.provider.as_str());
    println!("  active in MyKey auth: yes");
    Ok(())
}

async fn run_status() -> Result<(), String> {
    ensure_root("status");
    let target_uid = preferred_target_uid();
    let system_username = preferred_target_username()
        .ok_or_else(|| "Could not resolve the target Linux account.".to_string())?;

    let client = daemon_client::DaemonClient::connect().await?;
    let registry = load_registry(&client, target_uid, &system_username).await?;
    let local_auth = client.local_auth_status(target_uid).await?;
    client.disconnect().await;

    println!(
        "MyKey security-key registry for Linux account '{}':",
        registry.account_name
    );
    println!(
        "  - active in MyKey auth: {}",
        if local_auth.enabled && local_auth.has_stage("security_key") {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  - current MyKey local auth: {}",
        local_auth_summary_label(&local_auth)
    );
    if registry.keys.is_empty() {
        println!("  - no security keys enrolled");
        return Ok(());
    }

    println!("  - {} enrolled key(s)", registry.keys.len());
    for (idx, entry) in registry.keys.iter().enumerate() {
        println!(
            "  {}. {}",
            idx + 1,
            entry
                .nickname
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(entry.mykey_id.as_str())
        );
        println!("     id: {}", entry.mykey_id);
        println!("     enrolled: {}", entry.enrolled_at_utc);
        println!("     backend: {}", entry.provider.as_str());
        println!("     credential: {}", entry.credential_hint);
        println!(
            "     verification: {}",
            if entry.key_pin_required {
                "touch + key PIN"
            } else if entry.touch_required {
                "touch"
            } else {
                "unspecified"
            }
        );
    }

    Ok(())
}

async fn run_unenroll() -> Result<(), String> {
    ensure_root("unenroll");
    let target_uid = preferred_target_uid();
    let system_username = preferred_target_username()
        .ok_or_else(|| "Could not resolve the target Linux account.".to_string())?;

    let client = daemon_client::DaemonClient::connect().await?;
    let mut registry = load_registry(&client, target_uid, &system_username).await?;
    if registry.keys.is_empty() {
        client.disconnect().await;
        println!(
            "No MyKey security keys are currently enrolled for '{}'.",
            system_username
        );
        return Ok(());
    }

    require_elevated_password(
        target_uid,
        "security_key_manage",
        "Removing a MyKey security key requires verifying your Linux account password.",
    )?;

    let options: Vec<String> = registry
        .keys
        .iter()
        .map(|entry| {
            format!(
                "{} ({}, enrolled {})",
                entry
                    .nickname
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(entry.mykey_id.as_str()),
                entry.credential_hint,
                entry.enrolled_at_utc
            )
        })
        .collect();
    let option_refs: Vec<&str> = options.iter().map(|value| value.as_str()).collect();
    let selected = prompt_menu_selection("Select the key to unenroll", &option_refs)?;
    let removed = registry.keys.remove(selected);
    persist_registry(&client, target_uid, &system_username, &registry).await?;
    if registry.keys.is_empty() {
        client.disable_security_key_auth(target_uid).await?;
    }
    client.disconnect().await;

    println!(
        "Removed security key '{}'.",
        removed
            .nickname
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(removed.mykey_id.as_str())
    );
    Ok(())
}

fn local_auth_summary_label(status: &daemon_client::LocalAuthStatus) -> &'static str {
    if !status.enabled {
        if status.password_fallback_allowed {
            "password fallback only"
        } else {
            "unconfigured"
        }
    } else if status.has_stage("biometric") && status.has_stage("security_key") {
        "biometric -> security key -> pin"
    } else if status.has_stage("biometric") {
        "biometric -> pin"
    } else if status.has_stage("security_key") {
        "security key -> pin"
    } else if status.has_stage("pin") {
        "pin"
    } else {
        "other"
    }
}

fn run_test() -> Result<(), String> {
    ensure_security_key_runtime_available()?;
    let target_uid = preferred_target_uid();
    let username = auth_client::uid_to_username(target_uid)
        .ok_or_else(|| format!("Could not resolve a Linux account for uid={target_uid}."))?;

    println!(
        "Testing MyKey security-key authentication for '{}'. Touch your enrolled key now.",
        username
    );
    match auth_client::authenticate_user(&username) {
        Ok(()) => {
            println!("Security-key authentication succeeded.");
            Ok(())
        }
        Err(code) if auth_client::is_auth_failure(code) => {
            Err("Security-key authentication failed.".to_string())
        }
        Err(code) => Err(format!(
            "Security-key authentication failed through PAM service '{}': {}",
            auth_client::PAM_SERVICE,
            code
        )),
    }
}

async fn ensure_pin_prerequisite(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
) -> Result<(), String> {
    let pin_status = client.pin_status(target_uid).await?;
    if !pin_status.is_set {
        return Err(
            "MyKey security keys require a configured MyKey PIN fallback. Run: mykey-pin set"
                .to_string(),
        );
    }
    if pin_status.cooldown_remaining_secs > 0 {
        return Err(format!(
            "MyKey PIN is currently locked for {} seconds. Wait for the cooldown to expire before managing security keys.",
            pin_status.cooldown_remaining_secs
        ));
    }
    Ok(())
}

async fn load_registry(
    client: &daemon_client::DaemonClient,
    uid: u32,
    system_username: &str,
) -> Result<SecurityKeyRegistry, String> {
    let path = registry_path(uid);
    match std::fs::read(&path) {
        Ok(sealed) => {
            let plaintext = client.unseal_secret(&sealed).await?;
            let registry: SecurityKeyRegistry = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("Cannot parse security-key registry: {e}"))?;
            Ok(registry.normalised(system_username))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SecurityKeyRegistry {
            version: 1,
            account_name: system_username.to_string(),
            keys: Vec::new(),
        }),
        Err(e) => Err(format!(
            "Cannot read security-key registry from {}: {e}",
            path.display()
        )),
    }
}

async fn persist_registry(
    client: &daemon_client::DaemonClient,
    uid: u32,
    system_username: &str,
    registry: &SecurityKeyRegistry,
) -> Result<(), String> {
    let registry = registry.clone().normalised(system_username);
    let bytes = serde_json::to_vec_pretty(&registry)
        .map_err(|e| format!("Cannot serialise security-key registry: {e}"))?;
    let sealed = client.seal_secret(&bytes).await?;
    write_bytes_atomic(&registry_path(uid), &sealed, 0o600)?;
    sync_pam_u2f_authfile_at(Path::new(PAM_U2F_AUTHFILE), system_username, &registry)
}

fn registry_path(uid: u32) -> PathBuf {
    Path::new(AUTH_ROOT)
        .join(uid.to_string())
        .join(REGISTRY_FILENAME)
}

fn sync_pam_u2f_authfile_at(
    path: &Path,
    username: &str,
    registry: &SecurityKeyRegistry,
) -> Result<(), String> {
    let mut entries = read_pam_u2f_authfile_at(path)?;
    if registry.keys.is_empty() {
        entries.remove(username);
    } else {
        let joined = registry
            .keys
            .iter()
            .map(|entry| entry.pam_u2f_mapping.as_str())
            .collect::<Vec<_>>()
            .join(":");
        entries.insert(username.to_string(), joined);
    }

    if entries.is_empty() {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "Cannot remove empty security-key authfile {}: {e}",
                    path.display()
                ))
            }
        }
    }

    let mut body = String::new();
    for (user, mapping) in entries {
        body.push_str(&user);
        body.push(':');
        body.push_str(&mapping);
        body.push('\n');
    }
    write_bytes_atomic(path, body.as_bytes(), 0o600)
}

fn read_pam_u2f_authfile_at(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut entries = BTreeMap::new();
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            for (line_no, line) in contents.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let (user, mapping) = trimmed.split_once(':').ok_or_else(|| {
                    format!(
                        "Cannot parse {} line {}: expected '<user>:<mapping>'",
                        path.display(),
                        line_no + 1
                    )
                })?;
                entries.insert(user.to_string(), mapping.to_string());
            }
            Ok(entries)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("Cannot read {}: {e}", path.display())),
    }
}

fn enroll_with_pamu2fcfg(system_username: &str) -> Result<String, String> {
    let binary = resolve_existing_path(PAM_U2F_CFG_CANDIDATES).ok_or_else(|| {
        "Could not find pamu2fcfg. Install the pam-u2f package first.".to_string()
    })?;
    let output = Command::new(binary)
        .args([
            "-u",
            system_username,
            "-o",
            PAM_U2F_ORIGIN,
            "-i",
            PAM_U2F_APPID,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Could not launch pamu2fcfg: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        return Err(non_empty_message(
            stderr,
            "pamu2fcfg failed while enrolling the security key.".to_string(),
        ));
    }

    parse_mapping_fragment(&stdout)
}

fn parse_mapping_fragment(stdout: &str) -> Result<String, String> {
    let line = stdout
        .lines()
        .find(|value| !value.trim().is_empty())
        .ok_or_else(|| "pamu2fcfg did not return a registration mapping.".to_string())?;
    let (_user, mapping) = line
        .split_once(':')
        .ok_or_else(|| "pamu2fcfg returned an unexpected mapping format.".to_string())?;
    let mapping = mapping.trim();
    if mapping.is_empty() {
        return Err("pamu2fcfg returned an empty key mapping.".to_string());
    }
    Ok(mapping.to_string())
}

fn credential_hint_from_mapping(mapping: &str) -> String {
    let key_handle = mapping.split(',').next().unwrap_or(mapping);
    masked_tail(key_handle)
}

fn mapping_fingerprint(mapping: &str) -> String {
    let digest = Sha256::digest(mapping.as_bytes());
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn masked_tail(value: &str) -> String {
    let tail: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("************{tail}")
}

fn ensure_security_key_backend_for_enrollment() -> Result<(), String> {
    if resolve_existing_path(PAM_U2F_CFG_CANDIDATES).is_none() {
        return Err(
            "Could not find pamu2fcfg. Install the pam-u2f package before enrolling a security key."
                .to_string(),
        );
    }
    if resolve_existing_path(PAM_U2F_MODULE_CANDIDATES).is_none() {
        return Err(
            "Could not find pam_u2f.so. Install the pam-u2f package before enrolling a security key."
                .to_string(),
        );
    }
    Ok(())
}

fn ensure_security_key_runtime_available() -> Result<(), String> {
    if resolve_existing_path(PAM_SECURITY_KEY_SERVICE_CANDIDATES).is_none() {
        return Err(
            "Could not find /etc/pam.d/mykey-security-key-auth. Install MyKey's security-key PAM service first."
                .to_string(),
        );
    }
    if resolve_existing_path(PAM_U2F_MODULE_CANDIDATES).is_none() {
        return Err(
            "Could not find pam_u2f.so. Install the pam-u2f package before testing a security key."
                .to_string(),
        );
    }
    Ok(())
}

fn require_elevated_password(target_uid: u32, purpose: &str, intro: &str) -> Result<(), String> {
    match elevated_auth_precheck(target_uid) {
        HelperAuthResult::Success => {}
        HelperAuthResult::AuthFailed(message)
        | HelperAuthResult::RateLimited(message)
        | HelperAuthResult::Error(message) => return Err(message),
    }

    println!("{intro}");
    let password = rpassword::prompt_password("Linux account password: ")
        .map(Zeroizing::new)
        .map_err(|e| format!("Could not read Linux password: {e}"))?;

    match run_elevated_auth_helper(target_uid, purpose, password.as_bytes()) {
        HelperAuthResult::Success => Ok(()),
        HelperAuthResult::AuthFailed(message)
        | HelperAuthResult::RateLimited(message)
        | HelperAuthResult::Error(message) => Err(message),
    }
}

enum HelperAuthResult {
    Success,
    AuthFailed(String),
    RateLimited(String),
    Error(String),
}

fn elevated_auth_precheck(uid: u32) -> HelperAuthResult {
    let helper_path = match resolve_existing_path(ELEVATED_AUTH_HELPER_CANDIDATES) {
        Some(path) => path,
        None => {
            return HelperAuthResult::Error(
                "Could not find an installed mykey-elevated-auth helper.".to_string(),
            );
        }
    };

    let output = match Command::new(helper_path)
        .args(["status", "--uid", &uid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            return HelperAuthResult::Error(format!("Could not launch mykey-elevated-auth: {e}"));
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    match output.status.code() {
        Some(0) => HelperAuthResult::Success,
        Some(3) => HelperAuthResult::RateLimited(non_empty_message(
            stderr,
            "Elevated MyKey password auth is temporarily rate-limited.".to_string(),
        )),
        Some(2) => HelperAuthResult::Error(non_empty_message(
            stderr,
            "Elevated MyKey password verification failed.".to_string(),
        )),
        Some(code) => HelperAuthResult::Error(format!(
            "mykey-elevated-auth exited unexpectedly with status {code}"
        )),
        None => HelperAuthResult::Error(
            "mykey-elevated-auth terminated without an exit status".to_string(),
        ),
    }
}

fn run_elevated_auth_helper(uid: u32, purpose: &str, password: &[u8]) -> HelperAuthResult {
    let helper_path = match resolve_existing_path(ELEVATED_AUTH_HELPER_CANDIDATES) {
        Some(path) => path,
        None => {
            return HelperAuthResult::Error(
                "Could not find an installed mykey-elevated-auth helper.".to_string(),
            );
        }
    };

    let mut child = match Command::new(helper_path)
        .args(["verify", "--uid", &uid.to_string(), "--purpose", purpose])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return HelperAuthResult::Error(format!("Could not launch mykey-elevated-auth: {e}"));
        }
    };

    if let Some(stdin) = child.stdin.as_mut() {
        if let Err(e) = stdin.write_all(password) {
            let _ = child.kill();
            let _ = child.wait();
            return HelperAuthResult::Error(format!(
                "Could not send password to mykey-elevated-auth: {e}"
            ));
        }
    } else {
        let _ = child.kill();
        let _ = child.wait();
        return HelperAuthResult::Error(
            "mykey-elevated-auth did not expose a writable stdin".to_string(),
        );
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            return HelperAuthResult::Error(format!("Failed waiting for mykey-elevated-auth: {e}"));
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    match output.status.code() {
        Some(0) => HelperAuthResult::Success,
        Some(1) => HelperAuthResult::AuthFailed(non_empty_message(
            stderr,
            "Linux password verification failed.".to_string(),
        )),
        Some(3) => HelperAuthResult::RateLimited(non_empty_message(
            stderr,
            "Elevated MyKey password auth is temporarily rate-limited.".to_string(),
        )),
        Some(2) => HelperAuthResult::Error(non_empty_message(
            stderr,
            "Elevated MyKey password verification failed.".to_string(),
        )),
        Some(code) => HelperAuthResult::Error(format!(
            "mykey-elevated-auth exited unexpectedly with status {code}"
        )),
        None => HelperAuthResult::Error(
            "mykey-elevated-auth terminated without an exit status".to_string(),
        ),
    }
}

fn non_empty_message(message: String, fallback: String) -> String {
    if message.is_empty() {
        fallback
    } else {
        message
    }
}

fn prompt_optional(prompt: &str) -> Result<Option<String>, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|e| format!("Could not flush stdout: {e}"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("Could not read response: {e}"))?;
    let value = line.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

fn prompt_menu_selection(prompt: &str, options: &[&str]) -> Result<usize, String> {
    loop {
        println!("{prompt}:");
        for (idx, option) in options.iter().enumerate() {
            println!("  {}. {}", idx + 1, option);
        }
        print!("Selection: ");
        io::stdout()
            .flush()
            .map_err(|e| format!("Could not flush stdout: {e}"))?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Could not read response: {e}"))?;
        match line.trim().parse::<usize>() {
            Ok(value) if value >= 1 && value <= options.len() => return Ok(value - 1),
            _ => println!("Invalid selection."),
        }
    }
}

fn preferred_target_uid() -> u32 {
    if unsafe { libc::geteuid() } == 0 {
        std::env::var("SUDO_UID")
            .ok()
            .and_then(|uid| uid.parse::<u32>().ok())
            .unwrap_or_else(|| unsafe { libc::getuid() })
    } else {
        unsafe { libc::getuid() }
    }
}

fn preferred_target_username() -> Option<String> {
    if unsafe { libc::geteuid() } == 0 {
        if let Ok(value) = std::env::var("SUDO_USER") {
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }
    auth_client::uid_to_username(preferred_target_uid())
}

fn ensure_root(command: &str) {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "mykey-security-key {command} modifies /etc/mykey and must be run as root.\nRun: sudo mykey-security-key {command}"
        );
        std::process::exit(1);
    }
}

fn resolve_existing_path<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
}

fn now_recorded_at() -> (u64, String) {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (unix, Utc::now().to_rfc3339())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let parent_existed = parent.exists();
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    if !parent_existed {
        set_mode_if_supported(parent, 0o700)?;
    }

    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("security-keys"),
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
    ));

    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temp_path)
        .map_err(|e| format!("Cannot open temp file {}: {e}", temp_path.display()))?;

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|e| format!("Cannot open temp file {}: {e}", temp_path.display()))?;

    file.write_all(bytes)
        .map_err(|e| format!("Cannot write temp file {}: {e}", temp_path.display()))?;
    file.sync_all()
        .map_err(|e| format!("Cannot sync temp file {}: {e}", temp_path.display()))?;

    std::fs::rename(&temp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp_path);
        format!(
            "Cannot move temp file {} into {}: {e}",
            temp_path.display(),
            path.display()
        )
    })?;
    set_mode_if_supported(path, mode)
}

fn set_mode_if_supported(path: impl AsRef<Path>, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.as_ref().display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        masked_tail, parse_mapping_fragment, read_pam_u2f_authfile_at, sync_pam_u2f_authfile_at,
        SecurityKeyEnrollment, SecurityKeyProvider, SecurityKeyRegistry,
    };
    use std::path::Path;

    #[test]
    fn parse_mapping_fragment_accepts_standard_pamu2fcfg_output() {
        let mapping = parse_mapping_fragment("james:keyhandle,userkey,es256,+presence\n")
            .expect("mapping should parse");
        assert_eq!(mapping, "keyhandle,userkey,es256,+presence");
    }

    #[test]
    fn masked_tail_preserves_last_four_characters() {
        assert_eq!(masked_tail("abcdef123456"), "************3456");
    }

    #[test]
    fn sync_pam_u2f_authfile_rewrites_current_user_line() {
        let temp = std::env::temp_dir().join(format!(
            "mykey-security-key-authfile-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(temp.parent().expect("parent")).expect("create parent");
        std::fs::write(&temp, "alice:alice-mapping\n").expect("write initial authfile");
        let registry = SecurityKeyRegistry {
            version: 1,
            account_name: "james".to_string(),
            keys: vec![SecurityKeyEnrollment {
                mykey_id: "security-key-1234".to_string(),
                nickname: Some("Desk key".to_string()),
                provider: SecurityKeyProvider::PamU2f,
                enrolled_at_unix: 1,
                enrolled_at_utc: "2026-04-23T00:00:00Z".to_string(),
                credential_hint: "************abcd".to_string(),
                device_label: None,
                touch_required: true,
                key_pin_required: false,
                mapping_fingerprint: "1234".to_string(),
                pam_u2f_mapping: "keyhandle,userkey,es256,+presence".to_string(),
            }],
        };

        sync_pam_u2f_authfile_at(Path::new(&temp), "james", &registry).expect("sync authfile");
        let entries = read_pam_u2f_authfile_at(Path::new(&temp)).expect("read authfile");
        assert_eq!(
            entries.get("james").expect("james authfile line"),
            "keyhandle,userkey,es256,+presence"
        );
        assert_eq!(
            entries.get("alice").expect("alice authfile line"),
            "alice-mapping"
        );

        let _ = std::fs::remove_file(&temp);
    }
}
