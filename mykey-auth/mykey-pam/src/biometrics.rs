use crate::daemon_client::{DaemonClient, LocalAuthStatus};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const AUTH_ROOT: &str = "/etc/mykey/auth";
const REGISTRY_FILENAME: &str = "biometrics.registry.sealed";

pub async fn run(target_uid: u32, system_username: &str) {
    let client = match DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(2);
        }
    };

    if let Err(e) = ensure_pin_prerequisite(&client, target_uid).await {
        client.disconnect().await;
        eprintln!("{e}");
        std::process::exit(1);
    }

    match client.confirm_user_presence().await {
        Ok(true) => {}
        Ok(false) => {
            client.disconnect().await;
            eprintln!("MyKey user presence check was not approved.");
            std::process::exit(1);
        }
        Err(e) => {
            client.disconnect().await;
            eprintln!("Could not confirm user presence: {e}");
            std::process::exit(1);
        }
    }

    print_disclaimer();

    loop {
        println!();
        println!("Biometric actions:");
        println!("  1. Enroll");
        println!("  2. Unenroll");
        println!("  3. Status");
        println!("  4. Exit");

        match prompt_menu_selection(
            "Select an action",
            &["Enroll", "Unenroll", "Status", "Exit"],
        ) {
            Ok(0) => {
                if let Err(e) = enroll_flow(&client, target_uid, system_username).await {
                    eprintln!("{e}");
                }
            }
            Ok(1) => {
                if let Err(e) = unenroll_flow(&client, target_uid, system_username).await {
                    eprintln!("{e}");
                }
            }
            Ok(2) => {
                if let Err(e) = status_flow(&client, target_uid, system_username).await {
                    eprintln!("{e}");
                }
            }
            Ok(3) => break,
            Ok(_) => unreachable!(),
            Err(e) => {
                client.disconnect().await;
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    client.disconnect().await;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum ProviderKind {
    Fprintd,
    Howdy,
}

impl ProviderKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fprintd => "fprintd",
            Self::Howdy => "howdy",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Fprintd => "Fingerprint (fprintd)",
            Self::Howdy => "Face (Howdy)",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Hand {
    Left,
    Right,
}

impl Hand {
    fn label(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Finger {
    Thumb,
    Index,
    Middle,
    Ring,
    Pinky,
}

impl Finger {
    fn label(self) -> &'static str {
        match self {
            Self::Thumb => "thumb",
            Self::Index => "index",
            Self::Middle => "middle",
            Self::Ring => "ring",
            Self::Pinky => "pinky",
        }
    }

    fn fprintd_name(self, hand: Hand) -> &'static str {
        match (hand, self) {
            (Hand::Left, Self::Thumb) => "left-thumb",
            (Hand::Left, Self::Index) => "left-index-finger",
            (Hand::Left, Self::Middle) => "left-middle-finger",
            (Hand::Left, Self::Ring) => "left-ring-finger",
            (Hand::Left, Self::Pinky) => "left-little-finger",
            (Hand::Right, Self::Thumb) => "right-thumb",
            (Hand::Right, Self::Index) => "right-index-finger",
            (Hand::Right, Self::Middle) => "right-middle-finger",
            (Hand::Right, Self::Ring) => "right-ring-finger",
            (Hand::Right, Self::Pinky) => "right-little-finger",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BiometricRegistry {
    version: u32,
    #[serde(default)]
    account_name: String,
    #[serde(default)]
    enrollments: Vec<BiometricEnrollment>,
    #[serde(default, skip_serializing)]
    tracked_people: Vec<TrackedPerson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrackedPerson {
    name: String,
    created_at_unix: u64,
    created_at_utc: String,
    enrollments: Vec<BiometricEnrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BiometricEnrollment {
    mykey_id: String,
    provider: ProviderKind,
    recorded_at_unix: u64,
    recorded_at_utc: String,
    device_label: Option<String>,
    provider_reference: Option<String>,
    hand: Option<Hand>,
    finger: Option<Finger>,
}

impl BiometricRegistry {
    fn normalised(mut self, system_username: &str) -> Self {
        if self.version == 0 {
            self.version = 1;
        }
        if self.account_name.trim().is_empty() {
            self.account_name = system_username.to_string();
        }
        self.tracked_people
            .retain(|person| !person.name.trim().is_empty());
        if self.enrollments.is_empty() && !self.tracked_people.is_empty() {
            self.enrollments = self
                .tracked_people
                .iter()
                .flat_map(|person| person.enrollments.iter().cloned())
                .collect();
        }
        self.tracked_people.clear();
        self.enrollments
            .sort_by_key(|entry| entry.recorded_at_unix);
        self
    }

    fn provider_counts(&self) -> (usize, usize) {
        let fprint_count = self
            .enrollments
            .iter()
            .filter(|entry| entry.provider == ProviderKind::Fprintd)
            .count();
        let howdy_count = self
            .enrollments
            .iter()
            .filter(|entry| entry.provider == ProviderKind::Howdy)
            .count();
        (fprint_count, howdy_count)
    }

    fn registration_summary(&self) -> String {
        let (fprint_count, howdy_count) = self.provider_counts();
        format!("{fprint_count} fingerprint, {howdy_count} face")
    }

    fn providers_present(&self) -> BTreeSet<ProviderKind> {
        self.enrollments
            .iter()
            .map(|entry| entry.provider)
            .collect()
    }

    fn remove_provider(&mut self, provider: ProviderKind) {
        self.enrollments
            .retain(|entry| entry.provider != provider);
    }
}

async fn enroll_flow(
    client: &DaemonClient,
    target_uid: u32,
    system_username: &str,
) -> Result<(), String> {
    let mut registry = load_registry(client, target_uid, system_username).await?;

    loop {
        println!(
            "Enrolling biometrics for Linux account '{}'.",
            registry.account_name
        );
        let provider_mode = prompt_menu_selection(
            "Choose what to enroll",
            &[
                ProviderKind::Fprintd.label(),
                ProviderKind::Howdy.label(),
                "Both",
                "Cancel",
            ],
        )?;

        let mut successful_providers = Vec::new();
        match provider_mode {
            0 => {
                if enroll_fprintd(
                    client,
                    target_uid,
                    system_username,
                    &mut registry,
                )
                .await?
                {
                    successful_providers.push(ProviderKind::Fprintd);
                }
            }
            1 => {
                if enroll_howdy(
                    client,
                    target_uid,
                    system_username,
                    &mut registry,
                )
                .await?
                {
                    successful_providers.push(ProviderKind::Howdy);
                }
            }
            2 => {
                if enroll_fprintd(
                    client,
                    target_uid,
                    system_username,
                    &mut registry,
                )
                .await?
                {
                    successful_providers.push(ProviderKind::Fprintd);
                }
                if enroll_howdy(
                    client,
                    target_uid,
                    system_username,
                    &mut registry,
                )
                .await?
                {
                    successful_providers.push(ProviderKind::Howdy);
                }
            }
            3 => return Ok(()),
            _ => unreachable!(),
        }

        if !successful_providers.is_empty() {
            save_registry(client, target_uid, &registry).await?;
            select_active_backend(
                client,
                target_uid,
                &registry,
                successful_providers.last().copied(),
            )
            .await?;
        }

        if !prompt_yes_no("Would you like to perform another scan? [y/N]: ", false)? {
            return Ok(());
        }
    }
}

async fn unenroll_flow(
    client: &DaemonClient,
    target_uid: u32,
    system_username: &str,
) -> Result<(), String> {
    let mut registry = load_registry(client, target_uid, system_username).await?;
    let status = client.local_auth_status(target_uid).await?;

    println!("Unenroll options:");
    println!("  1. Remove biometrics from the MyKey auth chain only");
    println!("  2. Remove all fingerprint enrollments for this Linux account");
    println!("  3. Remove all face enrollments for this Linux account");
    println!("  4. Remove both provider data sets and disable biometric auth");
    println!("  5. Cancel");

    match prompt_menu_selection(
        "Choose an unenroll action",
        &[
            "Disable biometric auth only",
            "Delete all fingerprint data",
            "Delete all face data",
            "Delete both fingerprint and face data",
            "Cancel",
        ],
    )? {
        0 => {
            client.disable_biometric_backend(target_uid).await?;
            println!("Biometric auth removed from the MyKey auth chain. Provider data was kept.");
        }
        1 => {
            if delete_fprintd_data(system_username)? {
                registry.remove_provider(ProviderKind::Fprintd);
                save_registry(client, target_uid, &registry).await?;
                update_backend_after_provider_removal(
                    client,
                    target_uid,
                    &registry,
                    &status,
                    ProviderKind::Fprintd,
                )
                .await?;
                println!("Removed all fingerprint enrollment data for {system_username}.");
            }
        }
        2 => {
            if delete_howdy_data(system_username)? {
                registry.remove_provider(ProviderKind::Howdy);
                save_registry(client, target_uid, &registry).await?;
                update_backend_after_provider_removal(
                    client,
                    target_uid,
                    &registry,
                    &status,
                    ProviderKind::Howdy,
                )
                .await?;
                println!("Removed all face enrollment data for {system_username}.");
            }
        }
        3 => {
            let deleted_fprint = delete_fprintd_data(system_username)?;
            let deleted_howdy = delete_howdy_data(system_username)?;
            if deleted_fprint {
                registry.remove_provider(ProviderKind::Fprintd);
            }
            if deleted_howdy {
                registry.remove_provider(ProviderKind::Howdy);
            }
            if deleted_fprint || deleted_howdy {
                save_registry(client, target_uid, &registry).await?;
                if registry.providers_present().is_empty() {
                    client.disable_biometric_backend(target_uid).await?;
                } else {
                    select_active_backend(client, target_uid, &registry, None).await?;
                }
                println!("Updated biometric provider data and MyKey biometric policy.");
            }
        }
        4 => {}
        _ => unreachable!(),
    }

    Ok(())
}

async fn status_flow(
    client: &DaemonClient,
    target_uid: u32,
    system_username: &str,
) -> Result<(), String> {
    let registry = load_registry(client, target_uid, system_username).await?;
    let status = client.local_auth_status(target_uid).await?;

    println!(
        "MyKey biometric registry for Linux account '{}':",
        registry.account_name
    );
    if registry.enrollments.is_empty() {
        println!("  - no biometric registrations recorded");
    } else {
        println!("  - {}", registry.registration_summary());
    }

    if status.primary_method == "biometric" {
        println!(
            "Active MyKey biometric backend: {}",
            status.biometric_backend.as_deref().unwrap_or("unknown")
        );
    } else {
        println!("Active MyKey biometric backend: none");
    }
    Ok(())
}

async fn enroll_fprintd(
    client: &DaemonClient,
    target_uid: u32,
    system_username: &str,
    registry: &mut BiometricRegistry,
) -> Result<bool, String> {
    ensure_provider_installed(ProviderKind::Fprintd)?;
    let device_label = choose_device_label(
        "fingerprint reader",
        detect_fprintd_devices(),
        "No fingerprint reader was detected automatically.",
    )?;
    let hand = match prompt_menu_selection("Select the hand to register", &["Left", "Right"])? {
        0 => Hand::Left,
        1 => Hand::Right,
        _ => unreachable!(),
    };
    let finger = match prompt_menu_selection(
        "Select the finger to register",
        &["Thumb", "Index", "Middle", "Ring", "Pinky"],
    )? {
        0 => Finger::Thumb,
        1 => Finger::Index,
        2 => Finger::Middle,
        3 => Finger::Ring,
        4 => Finger::Pinky,
        _ => unreachable!(),
    };

    println!(
        "Starting fprintd enrollment for {} — {} {}.",
        registry.account_name,
        hand.label(),
        finger.label()
    );
    run_interactive_command(
        "fprintd-enroll",
        &["-f", finger.fprintd_name(hand), system_username],
    )?;

    let now = now_recorded_at();
    registry.enrollments.push(BiometricEnrollment {
        mykey_id: format!("fprintd-{}", now.0),
        provider: ProviderKind::Fprintd,
        recorded_at_unix: now.0,
        recorded_at_utc: now.1,
        device_label,
        provider_reference: None,
        hand: Some(hand),
        finger: Some(finger),
    });

    save_registry(client, target_uid, registry).await?;
    Ok(true)
}

async fn enroll_howdy(
    client: &DaemonClient,
    target_uid: u32,
    system_username: &str,
    registry: &mut BiometricRegistry,
) -> Result<bool, String> {
    ensure_provider_installed(ProviderKind::Howdy)?;
    let device_label = choose_device_label(
        "camera",
        detect_howdy_devices(),
        "No camera device was detected automatically.",
    )?;

    println!(
        "Starting Howdy enrollment for {}.",
        registry.account_name
    );
    run_interactive_command("howdy", &["-U", system_username, "add"])?;

    let now = now_recorded_at();
    registry.enrollments.push(BiometricEnrollment {
        mykey_id: format!("howdy-{}", now.0),
        provider: ProviderKind::Howdy,
        recorded_at_unix: now.0,
        recorded_at_utc: now.1,
        device_label,
        provider_reference: None,
        hand: None,
        finger: None,
    });

    save_registry(client, target_uid, registry).await?;
    Ok(true)
}

async fn ensure_pin_prerequisite(client: &DaemonClient, target_uid: u32) -> Result<(), String> {
    let pin_status = client.pin_status(target_uid).await?;
    if !pin_status.is_set {
        return Err(
            "MyKey biometrics require a configured MyKey PIN fallback. Run: mykey-pin set"
                .to_string(),
        );
    }
    Ok(())
}

async fn select_active_backend(
    client: &DaemonClient,
    target_uid: u32,
    registry: &BiometricRegistry,
    preferred: Option<ProviderKind>,
) -> Result<(), String> {
    let providers: Vec<_> = registry.providers_present().into_iter().collect();
    if providers.is_empty() {
        client.disable_biometric_backend(target_uid).await?;
        println!("No biometric provider remains active in MyKey.");
        return Ok(());
    }

    let selected = if providers.len() == 1 {
        providers[0]
    } else {
        println!(
            "MyKey can only treat one biometric backend as active at a time. The others stay enrolled but inactive."
        );
        let options: Vec<_> = providers.iter().map(|provider| provider.label()).collect();
        let default_index = preferred
            .and_then(|candidate| providers.iter().position(|provider| *provider == candidate))
            .unwrap_or(0);
        prompt_menu_selection_with_default(
            "Select the active MyKey biometric backend",
            &options,
            default_index,
        )
        .map(|idx| providers[idx])?
    };

    client
        .enable_biometric_backend(target_uid, selected.as_str())
        .await?;
    println!(
        "Active MyKey biometric backend set to {}.",
        selected.label()
    );
    Ok(())
}

async fn update_backend_after_provider_removal(
    client: &DaemonClient,
    target_uid: u32,
    registry: &BiometricRegistry,
    status: &LocalAuthStatus,
    removed_provider: ProviderKind,
) -> Result<(), String> {
    if status.primary_method != "biometric" {
        return Ok(());
    }

    let active = status
        .biometric_backend
        .as_deref()
        .and_then(|backend| match backend {
            "fprintd" => Some(ProviderKind::Fprintd),
            "howdy" => Some(ProviderKind::Howdy),
            _ => None,
        });

    if active != Some(removed_provider) {
        return Ok(());
    }

    select_active_backend(client, target_uid, registry, None).await
}

async fn load_registry(
    client: &DaemonClient,
    uid: u32,
    system_username: &str,
) -> Result<BiometricRegistry, String> {
    let path = registry_path(uid);
    match std::fs::read(&path) {
        Ok(blob) => {
            let plaintext = client.unseal_secret(&blob).await?;
            let registry: BiometricRegistry = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("Cannot parse {}: {e}", path.display()))?;
            Ok(registry.normalised(system_username))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BiometricRegistry {
            version: 1,
            account_name: system_username.to_string(),
            enrollments: Vec::new(),
            tracked_people: Vec::new(),
        }),
        Err(e) => Err(format!("Cannot read {}: {e}", path.display())),
    }
}

async fn save_registry(
    client: &DaemonClient,
    uid: u32,
    registry: &BiometricRegistry,
) -> Result<(), String> {
    let registry = registry.clone();
    let bytes = serde_json::to_vec_pretty(&registry)
        .map_err(|e| format!("Cannot serialise biometric registry: {e}"))?;
    let sealed = client.seal_secret(&bytes).await?;
    write_bytes_atomic(&registry_path(uid), &sealed, 0o600)
}

fn registry_path(uid: u32) -> PathBuf {
    Path::new(AUTH_ROOT)
        .join(uid.to_string())
        .join(REGISTRY_FILENAME)
}

fn ensure_provider_installed(provider: ProviderKind) -> Result<(), String> {
    match provider {
        ProviderKind::Fprintd => {
            if command_exists("fprintd-enroll") && command_exists("fprintd-delete") {
                return Ok(());
            }

            println!("fprintd is not installed.");
            if prompt_yes_no("Install the Arch package 'fprintd' now? [Y/n]: ", true)? {
                run_interactive_command("pacman", &["-S", "--needed", "fprintd"])?;
            }
            if command_exists("fprintd-enroll") && command_exists("fprintd-delete") {
                Ok(())
            } else {
                Err("fprintd is still not available.".to_string())
            }
        }
        ProviderKind::Howdy => {
            if command_exists("howdy") {
                return Ok(());
            }

            println!("Howdy is not installed.");
            if command_exists("paru") {
                if prompt_yes_no(
                    "Install the AUR package 'howdy' with paru now? [Y/n]: ",
                    true,
                )? {
                    run_interactive_command("paru", &["-S", "--needed", "howdy"])?;
                }
            } else if command_exists("yay") {
                if prompt_yes_no(
                    "Install the AUR package 'howdy' with yay now? [Y/n]: ",
                    true,
                )? {
                    run_interactive_command("yay", &["-S", "--needed", "howdy"])?;
                }
            } else {
                return Err(
                    "Howdy is not installed. Install the AUR package 'howdy' with your preferred helper, then rerun mykey-auth biometrics."
                        .to_string(),
                );
            }

            if command_exists("howdy") {
                Ok(())
            } else {
                Err("Howdy is still not available.".to_string())
            }
        }
    }
}

fn choose_device_label(
    device_kind: &str,
    detected_devices: Vec<String>,
    detection_failure_message: &str,
) -> Result<Option<String>, String> {
    if detected_devices.is_empty() {
        println!("{detection_failure_message}");
        match prompt_menu_selection(
            "Choose how to continue",
            &["Exit enrollment", "Enter a manual device label"],
        )? {
            0 => Err("Biometric enrollment cancelled.".to_string()),
            1 => Ok(Some(prompt_non_empty(&format!(
                "Enter a label for the {device_kind}: "
            ))?)),
            _ => unreachable!(),
        }
    } else {
        println!("Detected {device_kind} devices:");
        for (idx, device) in detected_devices.iter().enumerate() {
            println!("  {}. {}", idx + 1, device);
        }
        let options: Vec<&str> = detected_devices
            .iter()
            .map(|device| device.as_str())
            .collect();
        let idx = prompt_menu_selection("Confirm the device to use", &options)?;
        Ok(Some(detected_devices[idx].clone()))
    }
}

fn detect_fprintd_devices() -> Vec<String> {
    let output = Command::new("busctl")
        .args(["--system", "tree", "net.reactivated.Fprint"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("/net/reactivated/Fprint/Device/"))
        .map(ToString::to_string)
        .collect()
}

fn detect_howdy_devices() -> Vec<String> {
    let mut devices = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/video4linux") else {
        return devices;
    };
    for entry in entries.flatten() {
        let name_path = entry.path().join("name");
        if let Ok(name) = std::fs::read_to_string(&name_path) {
            let label = format!("{} ({})", name.trim(), entry.file_name().to_string_lossy());
            devices.push(label);
        }
    }
    devices
}

fn delete_fprintd_data(system_username: &str) -> Result<bool, String> {
    println!(
        "fprintd can only remove all enrolled fingerprints for the Linux account '{}', not individual MyKey-tracked people or scans.",
        system_username
    );
    if !prompt_yes_no(
        "Delete all fingerprint enrollments for this Linux account? [y/N]: ",
        false,
    )? {
        return Ok(false);
    }
    run_interactive_command("fprintd-delete", &[system_username])?;
    Ok(true)
}

fn delete_howdy_data(system_username: &str) -> Result<bool, String> {
    println!(
        "Howdy will clear all enrolled face models for the Linux account '{}'.",
        system_username
    );
    if !prompt_yes_no(
        "Delete all Howdy face models for this Linux account? [y/N]: ",
        false,
    )? {
        return Ok(false);
    }
    run_interactive_command("howdy", &["-U", system_username, "clear"])?;
    Ok(true)
}

fn command_exists(name: &str) -> bool {
    let Ok(output) = Command::new("sh")
        .args(["-c", &format!("command -v {name} >/dev/null 2>&1")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    else {
        return false;
    };
    output.success()
}

fn run_interactive_command(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("Could not start {program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

fn print_disclaimer() {
    println!("MyKey biometric setup");
    println!(
        "MyKey automatically tracks biometric metadata under the current Linux \
account name. It does not create or manage additional Linux users."
    );
    println!(
        "MyKey tracks biometric metadata and keeps it TPM-sealed, but the actual \
fingerprint and face templates remain owned by the upstream biometric stacks."
    );
}

fn prompt_non_empty(prompt: &str) -> Result<String, String> {
    loop {
        print!("{prompt}");
        io::stdout()
            .flush()
            .map_err(|e| format!("Could not flush stdout: {e}"))?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Could not read response: {e}"))?;
        let value = line.trim();
        if !value.is_empty() {
            return Ok(value.to_string());
        }
        println!("A value is required.");
    }
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool, String> {
    loop {
        print!("{prompt}");
        io::stdout()
            .flush()
            .map_err(|e| format!("Could not flush stdout: {e}"))?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Could not read response: {e}"))?;
        let input = line.trim().to_ascii_lowercase();
        if input.is_empty() {
            return Ok(default);
        }
        match input.as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer yes or no."),
        }
    }
}

fn prompt_menu_selection(prompt: &str, options: &[&str]) -> Result<usize, String> {
    prompt_menu_selection_with_default(prompt, options, 0)
}

fn prompt_menu_selection_with_default(
    prompt: &str,
    options: &[&str],
    default_index: usize,
) -> Result<usize, String> {
    loop {
        println!("{prompt}:");
        for (idx, option) in options.iter().enumerate() {
            if idx == default_index {
                println!("  {}. {} [default]", idx + 1, option);
            } else {
                println!("  {}. {}", idx + 1, option);
            }
        }
        print!("Selection: ");
        io::stdout()
            .flush()
            .map_err(|e| format!("Could not flush stdout: {e}"))?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Could not read response: {e}"))?;
        let input = line.trim();
        if input.is_empty() {
            return Ok(default_index);
        }
        match input.parse::<usize>() {
            Ok(value) if value >= 1 && value <= options.len() => return Ok(value - 1),
            _ => println!("Invalid selection."),
        }
    }
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
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    set_mode_if_supported(parent, 0o700)?;

    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("biometrics"),
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
    ));

    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temp_path)
        .map_err(|e| format!("Cannot open {}: {e}", temp_path.display()))?;

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|e| format!("Cannot open {}: {e}", temp_path.display()))?;

    file.write_all(bytes)
        .map_err(|e| format!("Cannot write {}: {e}", temp_path.display()))?;
    file.sync_all()
        .map_err(|e| format!("Cannot sync {}: {e}", temp_path.display()))?;
    std::fs::rename(&temp_path, path)
        .map_err(|e| format!("Cannot replace {}: {e}", path.display()))?;
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
    use super::*;

    #[test]
    fn normalised_migrates_legacy_people_into_single_account_registry() {
        let registry = BiometricRegistry {
            version: 0,
            account_name: String::new(),
            enrollments: Vec::new(),
            tracked_people: vec![
                TrackedPerson {
                    name: "James".to_string(),
                    created_at_unix: 1,
                    created_at_utc: "2026-04-21T23:45:20Z".to_string(),
                    enrollments: vec![BiometricEnrollment {
                        mykey_id: "fprintd-1".to_string(),
                        provider: ProviderKind::Fprintd,
                        recorded_at_unix: 1,
                        recorded_at_utc: "2026-04-21T23:45:20Z".to_string(),
                        device_label: Some("reader".to_string()),
                        provider_reference: None,
                        hand: Some(Hand::Right),
                        finger: Some(Finger::Index),
                    }],
                },
                TrackedPerson {
                    name: "Guest".to_string(),
                    created_at_unix: 2,
                    created_at_utc: "2026-04-21T23:52:43Z".to_string(),
                    enrollments: vec![BiometricEnrollment {
                        mykey_id: "howdy-2".to_string(),
                        provider: ProviderKind::Howdy,
                        recorded_at_unix: 2,
                        recorded_at_utc: "2026-04-21T23:52:43Z".to_string(),
                        device_label: Some("camera".to_string()),
                        provider_reference: Some("12".to_string()),
                        hand: None,
                        finger: None,
                    }],
                },
            ],
        }
        .normalised("james");

        assert_eq!(registry.version, 1);
        assert_eq!(registry.account_name, "james");
        assert_eq!(registry.enrollments.len(), 2);
        assert!(registry.tracked_people.is_empty());
        assert_eq!(registry.enrollments[0].mykey_id, "fprintd-1");
        assert_eq!(registry.enrollments[1].mykey_id, "howdy-2");
    }
}
