// main.rs — MyKey Migration Tool entry point.
//
// Supports two subcommands:
//   --enroll    Migrate secrets from an existing provider to MyKey TPM2-sealed storage.
//   --unenroll  Restore secrets from MyKey back to the previous provider.

mod daemon_client;
mod paths;
mod secrets_client;
mod storage;

use sha2::{Digest, Sha256};

fn wait_until<F>(timeout: std::time::Duration, interval: std::time::Duration, check: F) -> bool
where
    F: Fn() -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(interval);
    }
    check()
}

fn flush_stdout() {
    use std::io::Write;
    std::io::stdout().flush().unwrap_or(());
}

fn read_line() -> String {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap_or(0);
    buf
}

fn log_migrate_event(event: impl AsRef<str>) {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let path = paths::migrate_log_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = paths::ensure_private_dir(parent) {
            eprintln!("⚠ Could not create migration log directory: {e}");
            return;
        }
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("⚠ Could not open migration log {}: {e}", path.display());
            return;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = writeln!(file, "{timestamp} {}", event.as_ref()) {
        eprintln!("⚠ Could not write migration log {}: {e}", path.display());
    }
}

// ---------------------------------------------------------------------------
// Error-recovery helpers
// ---------------------------------------------------------------------------

/// Prompt the user to fix a problem, then verify it up to `max_attempts` times.
///
/// Prints `what_failed`, shows `user_instruction`, waits for Enter, then calls
/// `check()`.  Returns `true` as soon as `check()` returns `true`.  Returns
/// `false` (with a support link) if all attempts are exhausted.
fn pause_and_retry<F>(
    what_failed: &str,
    user_instruction: &str,
    check: F,
    max_attempts: u32,
) -> bool
where
    F: Fn() -> bool,
{
    println!();
    println!("⚠ {what_failed}");
    println!();
    println!("Please open a new terminal and run:");
    println!("  {user_instruction}");
    println!();

    for attempt in 1..=max_attempts {
        print!(
            "Press Enter when you have resolved the issue (attempt {attempt}/{max_attempts})..."
        );
        flush_stdout();
        read_line();

        if check() {
            println!("✓ Issue resolved. Continuing...");
            return true;
        }

        if attempt < max_attempts {
            println!("✗ Issue not yet resolved. Please try again.");
            println!("  {user_instruction}");
        }
    }

    println!();
    println!("✗ Could not resolve: {what_failed}");
    println!("  The process cannot continue.");
    println!();
    println!("  If unable to resolve the issue, please submit an issue or discussion:");
    println!("  GitHub:  https://github.com/JamesFromFL/mykey");
    println!("  Discord: https://discord.gg/ANnzz4vQEe");
    false
}

/// Print a fatal error with support links and exit.
fn fatal_with_support(what_failed: &str) -> ! {
    log_migrate_event(format!("fatal {what_failed}"));
    println!();
    println!("✗ Fatal: {what_failed}");
    println!();
    println!("  If unable to resolve the issue, please submit an issue or discussion:");
    println!("  GitHub:  https://github.com/JamesFromFL/mykey");
    println!("  Discord: https://discord.gg/ANnzz4vQEe");
    std::process::exit(1);
}

fn is_kwallet_provider(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    lower.contains("kwallet") || lower.contains("ksecretd")
}

fn is_gnome_keyring_provider(process_name: &str) -> bool {
    process_name.to_lowercase().contains("gnome-keyring")
}

fn is_keepassxc_provider(process_name: &str) -> bool {
    process_name.to_lowercase().contains("keepassxc")
}

fn prepare_unenroll_destination_for_gnome_keyring(
    info: &secrets_client::ProviderInfoFile,
    source_collections: &[secrets_client::SourceCollectionSpec],
) -> Result<secrets_client::DestinationPlan, String> {
    secrets_client::prepare_destination(info, source_collections)
}

fn prepare_unenroll_destination_for_keepassxc(
    info: &secrets_client::ProviderInfoFile,
    source_collections: &[secrets_client::SourceCollectionSpec],
) -> Result<secrets_client::DestinationPlan, String> {
    match secrets_client::prepare_destination(info, source_collections) {
        Ok(plan) => Ok(plan),
        Err(initial_err)
            if initial_err.contains("KeePassXC Secret Service integration is not ready") =>
        {
            println!();
            println!("KeePassXC is running, but no writable Secret Service group is exposed yet.");
            println!("Please:");
            println!("  1. Open or unlock your KeePassXC database");
            println!("  2. Open Database -> Database Settings -> Secret Service Integration");
            println!("  3. Enable Secret Service integration for a group");
            println!("  4. Keep KeePassXC and the database open");
            println!();

            let destination = std::cell::RefCell::new(None::<secrets_client::DestinationPlan>);
            let last_err = std::cell::RefCell::new(Some(initial_err.clone()));

            if wait_until(
                std::time::Duration::from_secs(120),
                std::time::Duration::from_secs(1),
                || match secrets_client::prepare_destination(info, source_collections) {
                    Ok(plan) => {
                        *destination.borrow_mut() = Some(plan);
                        true
                    }
                    Err(err) => {
                        *last_err.borrow_mut() = Some(err);
                        false
                    }
                },
            ) {
                return Ok(destination.into_inner().expect("destination set"));
            }

            for attempt in 1..=3 {
                print!("Press Enter when KeePassXC is ready (attempt {attempt}/3)...");
                flush_stdout();
                read_line();

                match secrets_client::prepare_destination(info, source_collections) {
                    Ok(plan) => {
                        *destination.borrow_mut() = Some(plan);
                        return Ok(destination.into_inner().expect("destination set"));
                    }
                    Err(err) => {
                        *last_err.borrow_mut() = Some(err.clone());
                        if attempt < 3 {
                            println!("✗ KeePassXC is still not ready.");
                            println!("  {err}");
                            println!(
                                "  Expose a database group through Secret Service Integration, then try again."
                            );
                        }
                    }
                }
            }

            Err(last_err.into_inner().unwrap_or_else(|| {
                "Could not prepare destination keychain for KeePassXC.".to_string()
            }))
        }
        Err(err) => Err(err),
    }
}

fn prepare_unenroll_destination_for_generic(
    info: &secrets_client::ProviderInfoFile,
    source_collections: &[secrets_client::SourceCollectionSpec],
) -> Result<secrets_client::DestinationPlan, String> {
    secrets_client::prepare_destination(info, source_collections)
}

fn prepare_unenroll_destination_for_kwallet(
    info: &secrets_client::ProviderInfoFile,
    source_collections: &[secrets_client::SourceCollectionSpec],
) -> Result<secrets_client::DestinationPlan, String> {
    match secrets_client::prepare_destination(info, source_collections) {
        Ok(plan) => Ok(plan),
        Err(initial_err)
            if is_kwallet_provider(&info.process_name)
                && initial_err.contains("no wallet is open or exported") =>
        {
            println!();
            println!("Triggering the KWallet wallet-open prompt...");
            match secrets_client::trigger_kwallet_wallet_prompt(&info.process_name) {
                Ok(wallet_name) => {
                    println!("  (If a KWallet dialog appears, complete it for '{wallet_name}' — this will continue automatically.)");
                    println!("  If KWallet asks how to create the wallet, choose \"Classic, blowfish encrypted file\"");
                    println!("  for the standard encrypted setup unless you already use GPG with KWallet.");
                    println!("  If you want GPG encryption, cancel this restore, configure a suitable GPG key");
                    println!("  for KWallet first, then run `mykey-migrate --unenroll` again.");
                }
                Err(err) => {
                    println!("  Could not trigger the KWallet prompt automatically.");
                    println!("  {err}");
                }
            }

            let destination = std::cell::RefCell::new(None::<secrets_client::DestinationPlan>);
            let last_err = std::cell::RefCell::new(Some(initial_err.clone()));

            if wait_until(
                std::time::Duration::from_secs(60),
                std::time::Duration::from_millis(500),
                || match secrets_client::prepare_destination(info, source_collections) {
                    Ok(plan) => {
                        *destination.borrow_mut() = Some(plan);
                        true
                    }
                    Err(err) => {
                        *last_err.borrow_mut() = Some(err);
                        false
                    }
                },
            ) {
                return Ok(destination.into_inner().expect("destination set"));
            }

            println!();
            println!("KWallet needs an unlocked wallet before restore can continue.");
            println!("Please:");
            println!("  1. Open KDE Wallet Manager");
            println!("  2. Open or create the wallet 'kdewallet'");
            println!("  3. Unlock it and keep it open");
            println!("  4. Ensure Secret Service compatibility is available/exported");
            println!();

            for attempt in 1..=3 {
                print!("Press Enter when KWallet is ready (attempt {attempt}/3)...");
                flush_stdout();
                read_line();

                match secrets_client::prepare_destination(info, source_collections) {
                    Ok(plan) => {
                        *destination.borrow_mut() = Some(plan);
                        return Ok(destination.into_inner().expect("destination set"));
                    }
                    Err(err) => {
                        *last_err.borrow_mut() = Some(err.clone());
                        if attempt < 3 {
                            println!("✗ KWallet is still not ready.");
                            println!("  {err}");
                            println!("  Open or unlock 'kdewallet', then try again.");
                        }
                    }
                }
            }

            Err(last_err.into_inner().unwrap_or_else(|| {
                "Could not prepare destination keychain for KWallet.".to_string()
            }))
        }
        Err(err) => Err(err),
    }
}

fn prepare_unenroll_destination(
    info: &secrets_client::ProviderInfoFile,
    source_collections: &[secrets_client::SourceCollectionSpec],
) -> Result<secrets_client::DestinationPlan, String> {
    if is_gnome_keyring_provider(&info.process_name) {
        prepare_unenroll_destination_for_gnome_keyring(info, source_collections)
    } else if is_kwallet_provider(&info.process_name) {
        prepare_unenroll_destination_for_kwallet(info, source_collections)
    } else if is_keepassxc_provider(&info.process_name) {
        prepare_unenroll_destination_for_keepassxc(info, source_collections)
    } else {
        prepare_unenroll_destination_for_generic(info, source_collections)
    }
}

fn finalize_unenroll_provider_enablement(
    info: &secrets_client::ProviderInfoFile,
    target_provider: &str,
) -> Result<(), String> {
    if is_gnome_keyring_provider(&info.process_name) {
        if let Some(ref svc) = info.service_name {
            let status = std::process::Command::new("systemctl")
                .args(["--user", "enable", svc.as_str()])
                .status()
                .map_err(|e| format!("Could not enable {svc}: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "Could not enable {svc}: systemctl exited with {status}"
                ));
            }
            println!("✓ {} enabled to start automatically.", target_provider);
        } else {
            println!(
                "✓ {} restore completed. Ensure this provider starts automatically in your session if needed.",
                target_provider
            );
        }
    } else if is_kwallet_provider(&info.process_name) {
        if !secrets_client::provider_ready(info) {
            return Err(
                "KWallet is not the active Secret Service provider after restore".to_string(),
            );
        }
        println!(
            "✓ KWallet restore completed. Secret Service compatibility is handled by KDE/D-Bus activation, so no separate unit enablement is required."
        );
    } else if is_keepassxc_provider(&info.process_name) {
        if !secrets_client::provider_ready(info) {
            return Err(
                "KeePassXC is not the active Secret Service provider after restore".to_string(),
            );
        }
        println!(
            "✓ KeePassXC restore completed. If you want D-Bus activation without launching the app first, create ~/.local/share/dbus-1/services/org.freedesktop.secrets.service with Exec=/usr/bin/keepassxc."
        );
    } else if let Some(ref svc) = info.service_name {
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", svc.as_str()])
            .status()
            .map_err(|e| format!("Could not enable {svc}: {e}"))?;
        if !status.success() {
            return Err(format!(
                "Could not enable {svc}: systemctl exited with {status}"
            ));
        }
        println!("✓ {} enabled to start automatically.", target_provider);
    } else {
        println!(
            "✓ {} restore completed. Ensure this provider starts automatically in your session if needed.",
            target_provider
        );
    }
    Ok(())
}

fn log_provider_inventory(prefix: &str, secrets: &[secrets_client::ProviderSecretInfo]) {
    log_migrate_event(format!("{prefix} inventory_count={}", secrets.len()));
    for (index, secret) in secrets.iter().enumerate() {
        let mut attr_keys: Vec<&str> = secret.attributes.keys().map(|key| key.as_str()).collect();
        attr_keys.sort_unstable();
        log_migrate_event(format!(
            "{prefix} item index={index} collection={} item={} label={} locked={:?} content_type={} value_hash_readable={} attr_keys={}",
            secret.collection_path,
            secret.item_path,
            secret.label,
            secret.locked,
            secret.content_type,
            secret.value_sha256.is_some(),
            attr_keys.join(",")
        ));
        if let Some(err) = &secret.value_read_error {
            log_migrate_event(format!(
                "{prefix} item index={index} value_read_error={err}"
            ));
        }
    }
}

fn read_source_secrets_for_enroll(
    info: &secrets_client::ProviderInfo,
) -> Result<Vec<secrets_client::MigratedItem>, String> {
    match secrets_client::read_all_secrets() {
        Ok(items) => Ok(items),
        Err(initial_err) if is_keepassxc_provider(&info.process_name) => {
            println!();
            println!("KeePassXC exposed at least one item but denied reading a secret value.");
            println!("MyKey cannot migrate metadata only; KeePassXC must allow mykey-migrate to read each secret.");
            println!("Please:");
            println!("  1. Keep the KeePassXC database unlocked");
            println!(
                "  2. Ensure the Secret Service exposed group contains the entries to migrate"
            );
            println!(
                "  3. When KeePassXC prompts for /usr/bin/mykey-migrate, choose Allow All & Future"
            );
            println!("  4. If you previously denied access, remove that remembered decision in KeePassXC's Secret Service access settings, then retry");
            println!();
            let inventory = secrets_client::list_provider_secrets().unwrap_or_default();
            log_provider_inventory("enroll keepassxc_read_failed_inventory", &inventory);
            log_migrate_event(format!(
                "enroll keepassxc_read_failed initial_error={initial_err}"
            ));

            let mut last_err = initial_err;
            for attempt in 1..=3 {
                print!("Press Enter when KeePassXC access is allowed (attempt {attempt}/3)...");
                flush_stdout();
                read_line();
                match secrets_client::read_all_secrets() {
                    Ok(items) => return Ok(items),
                    Err(err) => {
                        last_err = err;
                        let inventory = secrets_client::list_provider_secrets().unwrap_or_default();
                        log_provider_inventory(
                            &format!("enroll keepassxc_retry_{attempt}_inventory"),
                            &inventory,
                        );
                        log_migrate_event(format!(
                            "enroll keepassxc_retry_{attempt}_failed error={last_err}"
                        ));
                        if attempt < 3 {
                            println!("✗ KeePassXC still denied at least one secret read.");
                            println!("  {last_err}");
                        }
                    }
                }
            }
            Err(last_err)
        }
        Err(err) => Err(err),
    }
}

fn print_usage() {
    println!("MyKey Migration Tool");
    println!();
    println!("Usage:");
    println!("  mykey-migrate --enroll     Migrate secrets from existing provider to MyKey");
    println!("  mykey-migrate --unenroll   Restore secrets from MyKey back to previous provider");
}

fn main() {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("--enroll") => run_enroll(),
        Some("--unenroll") => run_unenroll(),
        _ => {
            print_usage();
            std::process::exit(0);
        }
    }
}

// ---------------------------------------------------------------------------
// --enroll
// ---------------------------------------------------------------------------

fn run_enroll() {
    // Step 1 — Root check
    if std::env::var("USER").unwrap_or_default() == "root" || nix::unistd::getuid().is_root() {
        eprintln!("Do not run mykey-migrate as root.");
        std::process::exit(1);
    }

    // Step 2 — Check mykey-daemon is running
    match daemon_client::DaemonClient::connect() {
        Err(_) => {
            eprintln!("mykey-daemon is not running.");
            eprintln!("Start it with:  sudo systemctl start mykey-daemon");
            eprintln!("If not installed: https://github.com/JamesFromFL/mykey");
            std::process::exit(1);
        }
        Ok(daemon) => run_enroll_with_daemon(daemon),
    }
}

fn run_enroll_with_daemon(daemon: daemon_client::DaemonClient) {
    // Step 3 — Detect what owns org.freedesktop.secrets
    let provider = secrets_client::detect_provider();

    match provider {
        // Step 4 — Nothing owns the bus
        Err(_) => {
            println!("No Secret Service provider is currently running.");
            println!();

            // Check what's installed
            let installed = secrets_client::find_installed_providers();

            if installed.is_empty() {
                println!("No known Secret Service providers are installed.");
                println!("There are no secrets to migrate.");
                println!();
                print!("Enable and start mykey-secrets as your Secret Service provider? [Y/n]: ");
                flush_stdout();
                let ans = read_line();
                if ans.trim().to_lowercase() != "n" {
                    let _ = std::process::Command::new("systemctl")
                        .args(["--user", "enable", "mykey-secrets"])
                        .status();
                    let _ = std::process::Command::new("systemctl")
                        .args(["--user", "start", "mykey-secrets"])
                        .status();
                    println!("✓ mykey-secrets enabled and started.");
                }
                return;
            }

            println!("The following Secret Service providers are installed but not running:");
            for (i, name) in installed.iter().enumerate() {
                println!("  {}. {}", i + 1, name);
            }
            println!();
            print!("Start one to migrate its secrets? Enter number or N to skip: ");
            flush_stdout();
            let ans = read_line();

            if ans.trim().to_lowercase() == "n" || ans.trim().is_empty() {
                println!("No provider started. Enabling and starting mykey-secrets...");
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "enable", "mykey-secrets"])
                    .status();
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "start", "mykey-secrets"])
                    .status();
                return;
            }

            if let Ok(idx) = ans.trim().parse::<usize>() {
                if idx >= 1 && idx <= installed.len() {
                    let chosen = &installed[idx - 1];
                    match secrets_client::start_provider_by_name(chosen) {
                        Ok(_) => {
                            println!("✓ {} started.", chosen);
                            // Re-detect and continue with migration
                            match secrets_client::detect_provider() {
                                Ok(info) => do_migration(info, daemon),
                                Err(e) => {
                                    fatal_with_support(&format!(
                                        "Could not connect after starting provider: {e}"
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            fatal_with_support(&format!("Failed to start {}: {e}", chosen));
                        }
                    }
                }
            }
        }

        // Step 5 — mykey-secrets already owns the bus — verify it is enabled
        Ok(ref info) if info.process_name.contains("mykey-secrets") => {
            let is_enabled = std::process::Command::new("systemctl")
                .args(["--user", "is-enabled", "--quiet", "mykey-secrets"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if is_enabled {
                println!("MyKey is already your Secret Service provider — running and enabled.");
                println!("Nothing to do.");
            } else {
                println!("MyKey is already running as your Secret Service provider.");
                println!("⚠ mykey-secrets is not enabled — enabling so it starts automatically...");
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "enable", "mykey-secrets"])
                    .status();
                println!("✓ mykey-secrets enabled.");
            }
        }

        // Step 6 — Third party provider is running
        Ok(info) => {
            do_migration(info, daemon);
        }
    }

    if !secrets_client::ss_still_owned() || secrets_client::is_mykey_secrets_running() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "enable", "mykey-secrets"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "start", "mykey-secrets"])
            .status();
    }
}

fn detected_provider_to_file(
    info: &secrets_client::ProviderInfo,
) -> secrets_client::ProviderInfoFile {
    secrets_client::ProviderInfoFile {
        process_name: info.process_name.clone(),
        service_name: info.service_name.clone(),
        package_name: info.package_name.clone(),
        keychain_path: info.keychain_path.clone(),
        keychain_deleted: false,
    }
}

fn restart_previous_provider(info: &secrets_client::ProviderInfo) {
    match secrets_client::start_provider(&detected_provider_to_file(info)) {
        Ok(_) => eprintln!("✓ {} restarted after enroll rollback.", info.process_name),
        Err(e) => eprintln!(
            "⚠ Could not restart {} after enroll rollback: {e}",
            info.process_name
        ),
    }
}

fn rollback_enroll_takeover(
    info: &secrets_client::ProviderInfo,
    activated_storage: Option<storage::ActivatedStorage>,
) {
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "mykey-secrets"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "mykey-secrets"])
        .status();

    if let Some(activated_storage) = activated_storage {
        if let Err(e) = activated_storage.rollback() {
            eprintln!("⚠ Could not restore previous MyKey storage after rollback: {e}");
        }
    }

    restart_previous_provider(info);
}

fn normalized_collection_label(label: &str) -> String {
    label.trim().to_lowercase()
}

fn secret_fingerprint(
    collection_label: &str,
    label: &str,
    attributes: &std::collections::HashMap<String, String>,
    content_type: &str,
) -> String {
    let mut pairs: Vec<String> = attributes.iter().map(|(k, v)| format!("{k}={v}")).collect();
    pairs.sort();
    format!(
        "{}\x00{label}\x00{content_type}\x00{}",
        normalized_collection_label(collection_label),
        pairs.join("\x00")
    )
}

fn fatal_on_storage_audit_issues(audit: &storage::StorageAudit, context: &str) {
    if audit.issues.is_empty() {
        return;
    }

    let sample: Vec<String> = audit
        .issues
        .iter()
        .take(5)
        .map(|issue| format!("{}: {}", issue.path.display(), issue.message))
        .collect();
    let mut details = sample.join("; ");
    if audit.issues.len() > sample.len() {
        details.push_str(&format!("; and {} more", audit.issues.len() - sample.len()));
    }

    fatal_with_support(&format!(
        "{context}: MyKey storage audit found {} issue(s) under {}. {}. \
         Storage was not modified.",
        audit.issues.len(),
        audit.base_dir.display(),
        details
    ));
}

fn stage_migrated_storage(
    collections: &[storage::StoredCollection],
    items: &[storage::StoredItem],
) -> Result<storage::StagedStorage, String> {
    let stage = storage::StagedStorage::new()?;

    for collection in collections {
        if let Err(e) = stage.save_collection(collection) {
            let msg = format!(
                "Failed to stage collection '{}' to disk: {e}",
                collection.label
            );
            return Err(match stage.discard() {
                Ok(_) => msg,
                Err(cleanup) => format!("{msg}. Cleanup also failed: {cleanup}"),
            });
        }
    }

    for item in items {
        if let Err(e) = stage.save_item(item) {
            let msg = format!("Failed to stage secret '{}' to disk: {e}", item.label);
            return Err(match stage.discard() {
                Ok(_) => msg,
                Err(cleanup) => format!("{msg}. Cleanup also failed: {cleanup}"),
            });
        }
    }

    Ok(stage)
}

fn do_migration(info: secrets_client::ProviderInfo, daemon: daemon_client::DaemonClient) {
    log_migrate_event(format!(
        "enroll start source_provider={} service={}",
        info.process_name,
        info.service_name.as_deref().unwrap_or("none")
    ));
    println!();
    println!(
        "Detected provider: {} ({})",
        info.process_name,
        info.service_name.as_deref().unwrap_or("no systemd service")
    );
    println!();
    println!("MyKey will:");
    println!();
    println!("  • Copy your secrets and seal them with your TPM2 chip");
    println!();
    println!("  • All sealed secrets are verified before the old provider is stopped");
    println!();
    println!("  • This may take some time depending on the number of secrets - Please be patient");
    println!();
    println!("  • Your original keychain will NOT be deleted (unless you choose to)");
    println!();
    println!(
        "⚠ Your previous Secret Service provider ({}) will be stopped so MyKey can take over. \
You can restore it at any time by running: mykey-migrate --unenroll",
        info.process_name
    );
    println!();
    print!("Proceed? [Y/n]: ");
    flush_stdout();
    let ans = read_line();
    if ans.trim().to_lowercase() == "n" {
        println!("Cancelled. Nothing was changed.");
        return;
    }

    let existing_audit = storage::audit_storage();
    fatal_on_storage_audit_issues(&existing_audit, "Before enrollment");
    log_migrate_event(format!(
        "enroll storage_audit parsed_items={} raw_entries={} issues={}",
        existing_audit.parsed_item_count(),
        existing_audit.raw_entry_count(),
        existing_audit.issues.len()
    ));
    println!();
    if existing_audit.is_legitimate_empty() {
        println!("Existing MyKey storage: empty.");
    } else {
        println!(
            "Existing MyKey storage: {} parsed secret(s), {} raw storage entries.",
            existing_audit.parsed_item_count(),
            existing_audit.raw_entry_count()
        );
    }

    if existing_audit.is_suspicious_empty() {
        fatal_with_support(
            "Existing MyKey storage looks non-empty on disk but no valid secrets could be parsed. \
             Enrollment was stopped so existing storage is not overwritten.",
        );
    }

    // Read secrets — fatal if provider is unreachable
    println!();
    println!("Reading secrets from {}...", info.process_name);
    let items = match read_source_secrets_for_enroll(&info) {
        Ok(i) => i,
        Err(e) => fatal_with_support(&format!(
            "Failed to read secrets from {}: {e}",
            info.process_name
        )),
    };
    println!("Found {} secret(s) across collection(s).", items.len());
    log_migrate_event(format!("enroll provider_read count={}", items.len()));

    let mut stored_collections = existing_audit.parsed_collections.clone();
    let mut stored_items = existing_audit.parsed_items.clone();
    let mut collection_label_by_id: std::collections::HashMap<String, String> = stored_collections
        .iter()
        .map(|collection| (collection.id.clone(), collection.label.clone()))
        .collect();
    let mut collection_id_by_label: std::collections::HashMap<String, String> = stored_collections
        .iter()
        .map(|collection| {
            (
                normalized_collection_label(&collection.label),
                collection.id.clone(),
            )
        })
        .collect();
    let mut collection_ids: std::collections::HashSet<String> =
        stored_collections.iter().map(|c| c.id.clone()).collect();
    let mut fingerprints: std::collections::HashSet<String> = stored_items
        .iter()
        .map(|item| {
            let collection_label = collection_label_by_id
                .get(&item.collection_id)
                .map(String::as_str)
                .unwrap_or(&item.collection_id);
            secret_fingerprint(
                collection_label,
                &item.label,
                &item.attributes,
                &item.content_type,
            )
        })
        .collect();

    let mut success = 0;
    let mut failed = 0;
    let mut skipped_existing = 0;

    for item in &items {
        let fingerprint = secret_fingerprint(
            &item.collection_label,
            &item.label,
            &item.attributes,
            &item.content_type,
        );
        if fingerprints.contains(&fingerprint) {
            skipped_existing += 1;
            println!(
                "Skipping existing: [{}] {}",
                item.collection_label, item.label
            );
            continue;
        }

        print!("Migrating: [{}] {}... ", item.collection_label, item.label);
        flush_stdout();

        match daemon.seal_secret(&item.plaintext) {
            Err(e) => {
                println!("✗ Seal failed: {e}");
                failed += 1;
            }
            Ok(sealed) => match daemon.unseal_secret(&sealed) {
                Err(e) => {
                    println!("✗ Verify failed: {e}");
                    failed += 1;
                }
                Ok(verified) => {
                    if verified != item.plaintext {
                        println!("✗ Mismatch after verify");
                        failed += 1;
                    } else {
                        println!("✓ Verified");
                        success += 1;

                        let normalized_label = normalized_collection_label(&item.collection_label);
                        let collection_id = collection_id_by_label
                            .get(&normalized_label)
                            .cloned()
                            .unwrap_or_else(|| item.collection_id.clone());

                        if collection_ids.insert(collection_id.clone()) {
                            stored_collections.push(storage::StoredCollection {
                                id: collection_id.clone(),
                                label: item.collection_label.clone(),
                                created: item.created,
                                modified: item.modified,
                            });
                            collection_label_by_id
                                .insert(collection_id.clone(), item.collection_label.clone());
                            collection_id_by_label.insert(normalized_label, collection_id.clone());
                        }

                        stored_items.push(storage::StoredItem {
                            id: uuid::Uuid::new_v4().to_string(),
                            collection_id,
                            label: item.label.clone(),
                            attributes: item.attributes.clone(),
                            sealed_value: sealed,
                            content_type: item.content_type.clone(),
                            created: item.created,
                            modified: item.modified,
                        });
                        fingerprints.insert(fingerprint);
                    }
                }
            },
        }
    }

    println!();
    println!("Migration planning complete.");
    println!(
        "  Existing in MyKey: {}",
        existing_audit.parsed_item_count()
    );
    println!("  New migrated:     {}", success);
    println!("  Already present:  {}", skipped_existing);
    println!("  Failed:           {}", failed);
    println!("  Final MyKey set:  {}", stored_items.len());
    log_migrate_event(format!(
        "enroll merge_plan existing={} new={} skipped={} failed={} final={}",
        existing_audit.parsed_item_count(),
        success,
        skipped_existing,
        failed,
        stored_items.len()
    ));

    if failed > 0 {
        fatal_with_support(&format!(
            "{failed} secret(s) failed to seal or verify. Provider has NOT been stopped. \
             Check /tmp/mykey-daemon.log and run mykey-migrate --enroll again."
        ));
    }

    let staged_storage = match stage_migrated_storage(&stored_collections, &stored_items) {
        Ok(stage) => stage,
        Err(e) => {
            fatal_with_support(&format!(
                "{e}. Check that {} is writable.",
                storage::base_dir().display()
            ));
        }
    };

    // Stop old provider without uninstalling its package. Migration should
    // manage runtime ownership of org.freedesktop.secrets, not remove software.
    println!();
    println!("Stopping {}...", info.process_name);
    if secrets_client::stop_provider(&info).is_err() {
        let stop_hint = if info.process_name.to_lowercase().contains("gnome-keyring") {
            "systemctl --user stop gnome-keyring-daemon.socket gnome-keyring-daemon.service"
                .to_string()
        } else if let Some(ref svc) = info.service_name {
            format!("systemctl --user stop {svc}")
        } else {
            format!("pkill -f {}", info.process_name)
        };

        if !pause_and_retry(
            &format!("Could not stop {}", info.process_name),
            &stop_hint,
            || !secrets_client::ss_still_owned(),
            3,
        ) {
            let _ = staged_storage.discard();
            fatal_with_support(&format!("Could not stop {}", info.process_name));
        }
    }
    println!("✓ {} stopped.", info.process_name);
    log_migrate_event(format!(
        "enroll source_provider_stopped {}",
        info.process_name
    ));

    let activated_storage = match staged_storage.activate() {
        Ok(activated_storage) => activated_storage,
        Err(e) => {
            restart_previous_provider(&info);
            fatal_with_support(&format!("Could not activate staged MyKey storage: {e}"));
        }
    };

    // Enable and start mykey-secrets
    println!("Enabling and starting mykey-secrets...");
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "enable", "mykey-secrets"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "start", "mykey-secrets"])
        .status();

    let mykey_ready = || {
        let mykey_is_active = std::process::Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", "mykey-secrets"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let mykey_is_enabled = std::process::Command::new("systemctl")
            .args(["--user", "is-enabled", "--quiet", "mykey-secrets"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        mykey_is_active && mykey_is_enabled && secrets_client::is_mykey_secrets_running()
    };

    if !wait_until(
        std::time::Duration::from_secs(8),
        std::time::Duration::from_millis(250),
        mykey_ready,
    ) {
        if !pause_and_retry(
            "mykey-secrets failed to start and claim org.freedesktop.secrets",
            "systemctl --user start mykey-secrets",
            mykey_ready,
            3,
        ) {
            rollback_enroll_takeover(&info, Some(activated_storage));
            fatal_with_support("mykey-secrets failed to start");
        }
    }
    println!("✓ mykey-secrets is running and enabled.");
    log_migrate_event("enroll mykey_secrets_ready");

    // Write provider info only after takeover is fully confirmed.
    if let Err(e) = secrets_client::write_provider_info(&info) {
        eprintln!("⚠ Could not write provider info: {e}");
        if !pause_and_retry(
            &format!(
                "Could not write provider info to {}",
                paths::provider_dir().display()
            ),
            "mkdir -p \"${XDG_DATA_HOME:-$HOME/.local/share}/mykey/provider\"",
            || secrets_client::write_provider_info(&info).is_ok(),
            3,
        ) {
            rollback_enroll_takeover(&info, Some(activated_storage));
            fatal_with_support("Could not write provider info after multiple attempts.");
        }
    }

    if let Err(e) = activated_storage.commit() {
        eprintln!("⚠ Could not remove previous MyKey storage backup: {e}");
        log_migrate_event(format!("enroll backup_commit_warning {e}"));
    }

    // Optional keychain deletion only makes sense after new secrets were copied
    // from the old provider into MyKey in this transaction.
    if success > 0 {
        if let Some(ref kpath) = info.keychain_path {
            prompt_delete_keychain(kpath);
        }
    } else if info.keychain_path.is_some() {
        println!();
        println!("No new secrets were copied from the old provider.");
        println!("The old keychain was left untouched.");
    }

    println!();
    println!("✓ Enrollment complete. MyKey is now your Secret Service provider.");
    log_migrate_event("enroll complete");
}

fn prompt_delete_keychain(keychain_path: &str) {
    println!();
    println!("═══════════════════════════════════════════════════");
    println!("Optional: Delete old keychain");
    println!("═══════════════════════════════════════════════════");
    println!("Your secrets have been migrated and TPM2-sealed.");
    println!("The old keychain ({}) still exists.", keychain_path);
    println!();
    println!("Deleting it is RECOMMENDED — it contains your secrets");
    println!("in a less secure software-encrypted format.");
    println!();
    println!("This is REVERSIBLE. If you uninstall MyKey, your secrets");
    println!("will be restored to a reinstalled provider.");
    println!();
    print!("Delete old keychain? [y/N]: ");
    flush_stdout();
    let ans = read_line();
    if ans.trim().to_lowercase() != "y" {
        println!("Keychain kept. You can delete it later by running mykey-migrate --enroll again.");
        return;
    }
    println!();
    print!("Are you sure? This cannot be undone without MyKey. [y/N]: ");
    flush_stdout();
    let confirm = read_line();
    if confirm.trim().to_lowercase() != "y" {
        println!("Keychain kept.");
        return;
    }
    match std::fs::remove_dir_all(keychain_path) {
        Ok(_) => {
            println!("✓ Old keychain deleted.");
            let _ = secrets_client::mark_keychain_deleted();
        }
        Err(e) => eprintln!("⚠ Could not delete keychain: {e}"),
    }
}

// ---------------------------------------------------------------------------
// --unenroll
// ---------------------------------------------------------------------------

fn run_unenroll() {
    log_migrate_event("unenroll start");
    // Step 1 — Root check
    if std::env::var("USER").unwrap_or_default() == "root" || nix::unistd::getuid().is_root() {
        eprintln!("Do not run mykey-migrate as root.");
        std::process::exit(1);
    }

    // Step 2 — Check mykey-daemon is running
    let daemon = match daemon_client::DaemonClient::connect() {
        Ok(d) => d,
        Err(_) => {
            eprintln!("mykey-daemon is not running. It is required for unenroll.");
            std::process::exit(1);
        }
    };

    // Step 3 — Read provider info and advise user of previous provider
    let info = secrets_client::read_provider_info().unwrap_or(secrets_client::ProviderInfoFile {
        process_name: String::new(),
        service_name: None,
        package_name: String::new(),
        keychain_path: None,
        keychain_deleted: false,
    });
    let has_prior = !info.process_name.is_empty();
    log_migrate_event(format!(
        "unenroll provider_info previous_provider={} service={} has_prior={}",
        if has_prior {
            info.process_name.as_str()
        } else {
            "none"
        },
        info.service_name.as_deref().unwrap_or("none"),
        has_prior
    ));

    println!();
    if has_prior {
        println!(
            "Previously registered Secret Service provider: {}",
            info.process_name
        );
        if let Some(ref svc) = info.service_name {
            println!("  Systemd service: {svc}");
        }
    } else {
        println!("No enrollment record found — MyKey may not have been set up via mykey-migrate.");
        println!("You can still restore secrets to a new provider.");
    }
    println!();

    // Step 4 — Warning
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║              MyKey Unenroll                          ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("⚠ WARNING: Continuing will remove your secrets from MyKey.");
    println!("  They will be restored to your chosen Secret Service provider.");
    println!("  If restoration fails for any reason, unenroll will halt");
    println!("  and your MyKey secrets will remain intact.");
    println!();

    // Step 5 — Provider selection
    // When no enrollment record exists, option 1 ("previously used") is hidden
    // and the remaining options are renumbered 1–5.
    println!("Where would you like to restore your secrets?");
    println!();
    if has_prior {
        println!("  1. {} (previously used)", info.process_name);
        println!("  2. gnome-keyring");
        println!("  3. KWallet");
        println!("  4. KeePassXC");
        println!("  5. Exit");
        println!("  6. None  ⚠ WARNING: your secrets will be deleted without a backup");
        println!();
        print!("Enter selection [1-6]: ");
    } else {
        println!("  1. gnome-keyring");
        println!("  2. KWallet");
        println!("  3. KeePassXC");
        println!("  4. Exit");
        println!("  5. None  ⚠ WARNING: your secrets will be deleted without a backup");
        println!();
        print!("Enter selection [1-5]: ");
    }
    flush_stdout();
    let raw = read_line();
    let trimmed = raw.trim();
    // Empty input selects option 1 (previously used, or gnome-keyring if no prior).
    let selection: &str = if trimmed.is_empty() { "1" } else { trimmed };

    // Normalize: when has_prior is false the menu is 1–5 instead of 1–6.
    // Map to the canonical 1–6 numbering so all downstream logic is uniform.
    let normalized: &str = if !has_prior {
        match selection {
            "1" => "2",
            "2" => "3",
            "3" => "4",
            "4" => "5",
            "5" => "6",
            other => other,
        }
    } else {
        selection
    };

    // Handle Exit
    if normalized == "5" {
        println!("Exiting. Nothing was changed.");
        return;
    }

    // Handle None
    if normalized == "6" {
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  ⚠  PERMANENT DELETION WARNING                              ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
        println!("You have chosen to unenroll WITHOUT migrating to a new provider.");
        println!();
        println!("This means:");
        println!("  • mykey-secrets will be stopped and disabled");
        println!("  • ALL secrets sealed in MyKey will be PERMANENTLY DELETED");
        println!("  • There will be NO Secret Service provider on your system");
        println!("  • Apps that rely on secrets (browsers, email, VPN) may break");
        println!("  • This action is NOT reversible");
        println!();
        print!("Are you absolutely sure? [y/N]: ");
        flush_stdout();
        let confirm1 = read_line();
        if confirm1.trim().to_lowercase() != "y" {
            println!("Cancelled. Nothing was changed.");
            return;
        }
        println!();
        println!("To confirm permanent deletion, type exactly:");
        println!("  Yes. Permanently delete all my keys without migrating to a new provider");
        println!();
        print!("> ");
        flush_stdout();
        let phrase = read_line();
        if phrase.trim()
            != "Yes. Permanently delete all my keys without migrating to a new provider"
        {
            println!("Phrase did not match. Cancelled.");
            return;
        }
        // Delete MyKey secrets from the user's private data dir.
        println!();
        println!("Deleting MyKey secrets...");
        let _ = storage::remove_all_storage();
        let _ = secrets_client::delete_provider_info();
        // Stop mykey-secrets
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", "mykey-secrets"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "mykey-secrets"])
            .status();
        println!("✓ MyKey secrets deleted.");
        println!("  mykey-secrets has been stopped and disabled.");
        println!("  No Secret Service provider is running on your system.");
        return;
    }

    // Determine target provider
    let target_provider = match normalized {
        "1" => info.process_name.clone(),
        "2" => "gnome-keyring-daemon".to_string(),
        "3" => {
            if secrets_client::check_provider_installed("kwalletd6") {
                "kwalletd6".to_string()
            } else if secrets_client::check_provider_installed("kwalletd5") {
                "kwalletd5".to_string()
            } else {
                "kwalletd6".to_string()
            }
        }
        "4" => "keepassxc".to_string(),
        _ => {
            eprintln!("Invalid selection.");
            std::process::exit(1);
        }
    };
    log_migrate_event(format!("unenroll selected_target {target_provider}"));

    // Step 6 — Install if not present
    let package_name = match target_provider.as_str() {
        "gnome-keyring-daemon" => "gnome-keyring",
        "kwalletd5" => "kwallet",
        "kwalletd6" => "kwallet6",
        "keepassxc" => "keepassxc",
        _ => target_provider.as_str(),
    };

    let source_audit = storage::audit_storage();
    fatal_on_storage_audit_issues(&source_audit, "Before unenroll");
    log_migrate_event(format!(
        "unenroll storage_audit parsed_items={} raw_entries={} issues={}",
        source_audit.parsed_item_count(),
        source_audit.raw_entry_count(),
        source_audit.issues.len()
    ));
    if source_audit.is_suspicious_empty() {
        fatal_with_support(
            "MyKey storage looks non-empty on disk but no valid secrets could be parsed. \
             Unenroll was stopped so MyKey storage is not deleted.",
        );
    }
    println!();
    if source_audit.is_legitimate_empty() {
        println!("MyKey storage audit: empty.");
    } else {
        println!(
            "MyKey storage audit: {} parsed secret(s), {} raw storage entries.",
            source_audit.parsed_item_count(),
            source_audit.raw_entry_count()
        );
    }

    if !secrets_client::check_provider_installed(&target_provider) {
        println!("Installing {}...", package_name);
        if let Err(_) = secrets_client::reinstall_provider(package_name) {
            let hint = secrets_client::install_cmd_hint(package_name);
            if !pause_and_retry(
                &format!("Could not install {package_name}"),
                &hint,
                || secrets_client::check_provider_installed(&target_provider),
                3,
            ) {
                fatal_with_support(&format!("Could not install {package_name}"));
            }
        }
        println!("✓ {} installed.", package_name);
    }

    // Step 7 — Stop and quiesce mykey-secrets before handing the bus to the target (FIX 1).
    println!("Stopping mykey-secrets...");
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "mykey-secrets"])
        .status();
    if secrets_client::is_mykey_secrets_running() {
        if !pause_and_retry(
            "mykey-secrets did not stop",
            "systemctl --user stop mykey-secrets",
            || !secrets_client::is_mykey_secrets_running(),
            3,
        ) {
            fatal_with_support("mykey-secrets did not stop");
        }
    }
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "mykey-secrets"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "reset-failed", "mykey-secrets"])
        .stderr(std::process::Stdio::null())
        .status();
    println!("✓ mykey-secrets stopped.");
    log_migrate_event("unenroll mykey_secrets_stopped");

    // Step 8 — Start chosen provider
    println!("Starting {}...", target_provider);

    // Build a temporary ProviderInfo for start_provider
    let tmp_info = secrets_client::ProviderInfoFile {
        process_name: target_provider.clone(),
        service_name: if normalized == "1" {
            // Restore the exact service name that was recorded at enroll time.
            info.service_name.clone()
        } else {
            match target_provider.as_str() {
                "gnome-keyring-daemon" => Some("gnome-keyring-daemon.service".to_string()),
                "kwalletd5" => Some("kwalletd5.service".to_string()),
                "kwalletd6" => None,
                _ => None,
            }
        },
        package_name: package_name.to_string(),
        keychain_path: None,
        keychain_deleted: info.keychain_deleted,
    };

    let rollback_mykey = || {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "reset-failed", "mykey-secrets"])
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "enable", "mykey-secrets"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "start", "mykey-secrets"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    };

    if let Err(_) = secrets_client::start_provider(&tmp_info) {
        let svc_hint = if is_kwallet_provider(&target_provider) {
            "kwalletd6".to_string()
        } else {
            tmp_info
                .service_name
                .as_deref()
                .map(|s| format!("systemctl --user start {s}"))
                .unwrap_or_else(|| format!("{} &", target_provider))
        };
        if !pause_and_retry(
            &format!("{target_provider} did not become ready for Secret Service restore"),
            &svc_hint,
            || secrets_client::provider_ready(&tmp_info),
            3,
        ) {
            rollback_mykey();
            fatal_with_support(&format!("Could not start {target_provider}"));
        }
    }
    println!("✓ {} is running", target_provider);
    log_migrate_event(format!("unenroll target_ready {target_provider}"));

    // Step 9 — Load MyKey secrets and build the source collection map before
    // preparing the destination. This lets the destination plan preserve
    // collection layout where the target provider supports it.
    let collections = source_audit.parsed_collections.clone();
    let all_items = source_audit.parsed_items.clone();
    let item_collection_ids: std::collections::HashSet<String> = all_items
        .iter()
        .map(|item| item.collection_id.clone())
        .collect();
    let mut source_collections: Vec<secrets_client::SourceCollectionSpec> = Vec::new();
    for col in &collections {
        if item_collection_ids.contains(&col.id) {
            source_collections.push(secrets_client::SourceCollectionSpec {
                id: col.id.clone(),
                label: col.label.clone(),
            });
        }
    }

    // Step 10 — Prepare the destination keychain(s).
    println!();
    println!("Preparing destination keychain (a dialog may appear — please complete it)...");
    let destination = match prepare_unenroll_destination(&tmp_info, &source_collections) {
        Ok(plan) => plan,
        Err(e) => {
            rollback_mykey();
            fatal_with_support(&format!("Could not prepare destination keychain: {e}"));
        }
    };
    println!("✓ Destination keychain ready.");
    log_migrate_event(format!("unenroll destination_ready {target_provider}"));

    // Step 11 — Restore from MyKey into the validated destination.
    println!("Found {} secret(s) in MyKey storage.", all_items.len());
    log_migrate_event(format!("unenroll source_items count={}", all_items.len()));

    let strict_provider_matching = is_gnome_keyring_provider(&target_provider)
        || !is_kwallet_provider(&target_provider) && !is_keepassxc_provider(&target_provider);
    let keepassxc_matching = is_keepassxc_provider(&target_provider);
    let attributes_include_expected = |actual: &std::collections::HashMap<String, String>,
                                       expected: &std::collections::HashMap<String, String>|
     -> bool {
        expected
            .iter()
            .all(|(key, expected_value)| actual.get(key) == Some(expected_value))
    };
    let fingerprint_parts = |collection_path: &str,
                             label: &str,
                             attributes: &std::collections::HashMap<String, String>,
                             content_type: &str,
                             value_sha256: Option<&str>|
     -> String {
        let mut pairs: Vec<String> = attributes.iter().map(|(k, v)| format!("{k}={v}")).collect();
        pairs.sort();
        let collection_path = if strict_provider_matching {
            collection_path
        } else {
            ""
        };
        let content_type = if strict_provider_matching {
            content_type
        } else {
            ""
        };
        let value_sha256 = value_sha256.unwrap_or("");
        format!(
            "{collection_path}\x00{label}\x00{content_type}\x00{}\x00{value_sha256}",
            pairs.join("\x00"),
        )
    };

    let secrets_to_restore: Vec<&storage::StoredItem> = if info.keychain_deleted {
        println!("Old keychain was deleted — restoring all secrets.");
        all_items.iter().collect()
    } else {
        let existing = match secrets_client::list_provider_secrets() {
            Ok(existing) => existing,
            Err(e) => {
                rollback_mykey();
                fatal_with_support(&format!(
                    "Could not list existing secrets in {target_provider}: {e}. \
                     MyKey storage NOT deleted."
                ));
            }
        };
        log_provider_inventory("unenroll existing_provider", &existing);
        let fingerprint = |item: &storage::StoredItem| -> String {
            fingerprint_parts(
                destination
                    .collection_for_source(&item.collection_id)
                    .as_str(),
                &item.label,
                &item.attributes,
                &item.content_type,
                None,
            )
        };
        let new_only: Vec<&storage::StoredItem> = all_items
            .iter()
            .filter(|item| {
                if strict_provider_matching {
                    let existing_fingerprints: std::collections::HashSet<String> = existing
                        .iter()
                        .map(|secret| {
                            fingerprint_parts(
                                &secret.collection_path,
                                &secret.label,
                                &secret.attributes,
                                &secret.content_type,
                                None,
                            )
                        })
                        .collect();
                    !existing_fingerprints.contains(&fingerprint(item))
                } else {
                    !existing.iter().any(|secret| {
                        secret.label == item.label
                            && attributes_include_expected(&secret.attributes, &item.attributes)
                    })
                }
            })
            .collect();
        println!(
            "Restoring {} new secret(s) not in old keychain.",
            new_only.len()
        );
        new_only
    };

    let mut success = 0;
    let mut failed = 0;
    let mut expected_after_restore: Vec<(
        String,
        String,
        std::collections::HashMap<String, String>,
        String,
        String,
    )> = Vec::new();

    for item in &secrets_to_restore {
        print!("Restoring: {}... ", item.label);
        flush_stdout();
        match daemon.unseal_secret(&item.sealed_value) {
            Ok(plaintext) => {
                let value_sha256 = hex::encode(Sha256::digest(&plaintext));
                match secrets_client::write_secret_to_provider(
                    destination.collection_for_source(&item.collection_id),
                    &item.label,
                    &item.attributes,
                    &plaintext,
                    &item.content_type,
                ) {
                    Ok(_) => {
                        println!("✓");
                        success += 1;
                        expected_after_restore.push((
                            destination
                                .collection_for_source(&item.collection_id)
                                .as_str()
                                .to_string(),
                            item.label.clone(),
                            item.attributes.clone(),
                            item.content_type.clone(),
                            value_sha256,
                        ));
                    }
                    Err(e) => {
                        println!("✗ {e}");
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                println!("✗ {e}");
                failed += 1;
            }
        }
    }

    // Step 12 — Verify writes before MyKey data is deleted.
    println!();
    println!(
        "Restore complete. Restored: {}  Failed: {}",
        success, failed
    );
    log_migrate_event(format!(
        "unenroll restore_result success={success} failed={failed}"
    ));

    if failed > 0 {
        eprintln!("  Restarting mykey-secrets...");
        rollback_mykey();
        fatal_with_support(&format!(
            "{failed} secret(s) failed to restore to {target_provider}. \
             MyKey storage NOT deleted."
        ));
    }

    let provider_after_restore = match secrets_client::list_provider_secrets() {
        Ok(secrets) => secrets,
        Err(e) => {
            rollback_mykey();
            fatal_with_support(&format!(
                "Could not verify restored secrets in {target_provider}: {e}. \
                 MyKey storage NOT deleted."
            ));
        }
    };
    log_provider_inventory("unenroll after_restore_provider", &provider_after_restore);

    let missing_count = if strict_provider_matching {
        let actual_after_restore: std::collections::HashSet<String> = provider_after_restore
            .iter()
            .map(|secret| {
                fingerprint_parts(
                    &secret.collection_path,
                    &secret.label,
                    &secret.attributes,
                    &secret.content_type,
                    secret.value_sha256.as_deref(),
                )
            })
            .collect();
        expected_after_restore
            .iter()
            .filter(
                |(collection_path, label, attributes, content_type, value_sha256)| {
                    let expected = fingerprint_parts(
                        collection_path,
                        label,
                        attributes,
                        content_type,
                        Some(value_sha256.as_str()),
                    );
                    !actual_after_restore.contains(&expected)
                },
            )
            .count()
    } else {
        expected_after_restore
            .iter()
            .filter(
                |(_collection_path, label, attributes, _content_type, value_sha256)| {
                    !provider_after_restore.iter().any(|secret| {
                        let metadata_matches = secret.label == *label
                            && attributes_include_expected(&secret.attributes, attributes);
                        metadata_matches
                            && if keepassxc_matching {
                                match secret.value_sha256.as_deref() {
                                    Some(actual) => actual == value_sha256,
                                    None => true,
                                }
                            } else {
                                secret
                                    .value_sha256
                                    .as_deref()
                                    .map(|actual| actual == value_sha256)
                                    .unwrap_or(true)
                            }
                    })
                },
            )
            .count()
    };
    if missing_count > 0 {
        rollback_mykey();
        fatal_with_support(&format!(
            "Post-restore verification failed: {} restored secret(s) are not visible in {target_provider}. \
             MyKey storage NOT deleted.",
            missing_count
        ));
    }
    if keepassxc_matching {
        let metadata_only_verified = expected_after_restore
            .iter()
            .filter(
                |(_collection_path, label, attributes, _content_type, _value_sha256)| {
                    provider_after_restore.iter().any(|secret| {
                        secret.value_sha256.is_none()
                            && secret.label == *label
                            && attributes_include_expected(&secret.attributes, attributes)
                    })
                },
            )
            .count();
        if metadata_only_verified > 0 {
            log_migrate_event(format!(
                "unenroll keepassxc_metadata_only_verified count={metadata_only_verified}"
            ));
        }
    }

    println!("✓ Restore verified in {}.", target_provider);
    log_migrate_event(format!("unenroll restore_verified {target_provider}"));

    // Step 13 — Ensure the chosen provider remains enabled for future logins.
    if let Err(e) = finalize_unenroll_provider_enablement(&tmp_info, &target_provider) {
        rollback_mykey();
        fatal_with_support(&format!(
            "Could not finalize {target_provider} after restore: {e}. \
             MyKey storage NOT deleted."
        ));
    }
    log_migrate_event(format!("unenroll provider_finalized {target_provider}"));

    // Step 14 — Clean up MyKey storage
    println!("Cleaning up MyKey storage...");
    if let Err(e) = storage::remove_all_storage() {
        eprintln!("⚠ {e}");
        if !pause_and_retry(
            &format!("Could not remove {}", storage::base_dir().display()),
            "rm -rf \"${XDG_DATA_HOME:-$HOME/.local/share}/mykey/secrets\"",
            || !storage::base_dir().exists(),
            3,
        ) {
            fatal_with_support(&format!(
                "Could not remove {}",
                storage::base_dir().display()
            ));
        }
    }
    println!("✓ {} removed.", storage::base_dir().display());

    if let Err(e) = secrets_client::delete_provider_info() {
        eprintln!("⚠ Could not remove provider info: {e}");
        if !pause_and_retry(
            &format!("Could not remove {}", paths::provider_info_path().display()),
            "rm -f \"${XDG_DATA_HOME:-$HOME/.local/share}/mykey/provider/info.json\"",
            || !paths::provider_info_path().exists(),
            3,
        ) {
            fatal_with_support(&format!(
                "Could not remove {}",
                paths::provider_info_path().display()
            ));
        }
    }
    println!("✓ Provider info removed.");

    // Remove the mykey-secrets autostart entry — warn only on failure
    match secrets_client::remove_mykey_autostart() {
        Ok(_) => println!("✓ mykey-secrets autostart entry removed."),
        Err(e) => eprintln!("⚠ Could not remove autostart entry: {e}"),
    }

    // Disable the mykey-secrets systemd user unit so it does not restart on next login.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "mykey-secrets"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    println!("✓ mykey-secrets disabled.");

    println!();
    println!(
        "✓ Unenroll complete. {} is now your Secret Service provider.",
        target_provider
    );
    log_migrate_event(format!(
        "unenroll complete target_provider={target_provider}"
    ));
}
