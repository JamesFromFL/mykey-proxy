// mykey-auth — unified local authentication helper for MyKey.
//
// Phase A behavior:
//   - acts as the trusted helper behind pam_mykey.so
//   - authenticates using the existing MyKey PIN backend
//   - keeps room for future biometric-first auth before PIN fallback

#[path = "../biometrics.rs"]
mod biometrics;
#[path = "../daemon_client.rs"]
mod daemon_client;
#[path = "../pam_integration.rs"]
mod pam_integration;

use std::io::Read;
use std::io::{self, Write};

use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let parsed = parse_args(&args).unwrap_or_else(|msg| {
        eprintln!("{msg}");
        print_usage();
        std::process::exit(2);
    });

    match parsed {
        Command::Authenticate {
            target_uid,
            pin_from_stdin,
        } => run_authenticate(target_uid, pin_from_stdin).await,
        Command::Preflight { target_uid } => run_preflight(target_uid).await,
        Command::Enable => run_enable().await,
        Command::Disable => run_disable(),
        Command::Biometrics => run_biometrics().await,
        Command::Login => run_login(),
        Command::Logout => run_logout(),
        Command::Status => run_status().await,
    }
}

#[derive(Debug, Clone, Copy)]
enum Command {
    Authenticate {
        target_uid: u32,
        pin_from_stdin: bool,
    },
    Preflight {
        target_uid: u32,
    },
    Enable,
    Disable,
    Biometrics,
    Login,
    Logout,
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthReadiness {
    Ready,
    Ignore(String),
    Locked(String),
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    match args.get(1).map(|s| s.as_str()) {
        Some("authenticate") => {
            parse_uid_command(args, true).map(|(target_uid, pin_from_stdin)| {
                Command::Authenticate {
                    target_uid,
                    pin_from_stdin,
                }
            })
        }
        Some("preflight") => {
            parse_uid_command(args, false).map(|(target_uid, _)| Command::Preflight { target_uid })
        }
        Some("enable") if args.len() == 2 => Ok(Command::Enable),
        Some("disable") if args.len() == 2 => Ok(Command::Disable),
        Some("biometrics") if args.len() == 2 => Ok(Command::Biometrics),
        Some("login") if args.len() == 2 => Ok(Command::Login),
        Some("logout") if args.len() == 2 => Ok(Command::Logout),
        Some("status") if args.len() == 2 => Ok(Command::Status),
        Some(other) => Err(format!("Unknown or malformed command: {other}")),
        None => Err("Missing command.".to_string()),
    }
}

fn parse_uid_command(args: &[String], allow_pin_stdin: bool) -> Result<(u32, bool), String> {
    let mut target_uid = None;
    let mut pin_from_stdin = false;
    let mut idx = 2;
    while idx < args.len() {
        match args[idx].as_str() {
            "--uid" => {
                let value = args
                    .get(idx + 1)
                    .ok_or_else(|| "Missing value for --uid.".to_string())?;
                target_uid = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| format!("Invalid uid: {value}"))?,
                );
                idx += 2;
            }
            "--pin-stdin" => {
                if !allow_pin_stdin {
                    return Err("--pin-stdin is only valid for authenticate.".to_string());
                }
                pin_from_stdin = true;
                idx += 1;
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    let target_uid = target_uid.ok_or_else(|| "Missing required --uid argument.".to_string())?;
    Ok((target_uid, pin_from_stdin))
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  mykey-auth enable");
    eprintln!("  mykey-auth disable");
    eprintln!("  mykey-auth biometrics");
    eprintln!("  mykey-auth login");
    eprintln!("  mykey-auth logout");
    eprintln!("  mykey-auth status");
    eprintln!("  mykey-auth authenticate --uid <uid> --pin-stdin   (internal)");
    eprintln!("  mykey-auth preflight --uid <uid>                  (internal)");
}

async fn run_authenticate(target_uid: u32, pin_from_stdin: bool) {
    if !pin_from_stdin {
        eprintln!(
            "MyKey biometric-first authentication is not configured yet. \
Use pam_mykey's PIN backend for now."
        );
        std::process::exit(2);
    }

    let client = match daemon_client::DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(2);
        }
    };

    match auth_readiness_from_client(&client, target_uid).await {
        Ok(AuthReadiness::Ready) => {}
        Ok(AuthReadiness::Ignore(msg)) => {
            client.disconnect().await;
            eprintln!("{msg}");
            std::process::exit(4);
        }
        Ok(AuthReadiness::Locked(msg)) => {
            client.disconnect().await;
            eprintln!("{msg}");
            std::process::exit(3);
        }
        Err(e) => {
            client.disconnect().await;
            eprintln!("{e}");
            std::process::exit(2);
        }
    }

    let pin = match read_pin_from_stdin() {
        Ok(pin) if !pin.is_empty() => pin,
        Ok(_) => {
            client.disconnect().await;
            eprintln!("No PIN data was provided on standard input.");
            std::process::exit(2);
        }
        Err(e) => {
            client.disconnect().await;
            eprintln!("Failed to read PIN from standard input: {e}");
            std::process::exit(2);
        }
    };

    let result = client.pin_verify(target_uid, pin.as_slice()).await;
    client.disconnect().await;

    match result {
        Ok(true) => std::process::exit(0),
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("MyKey authentication failed: {e}");
            std::process::exit(2);
        }
    }
}

async fn run_preflight(target_uid: u32) {
    let client = match daemon_client::DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(2);
        }
    };

    let readiness = auth_readiness_from_client(&client, target_uid).await;
    client.disconnect().await;

    match readiness {
        Ok(AuthReadiness::Ready) => std::process::exit(0),
        Ok(AuthReadiness::Ignore(msg)) => {
            eprintln!("{msg}");
            std::process::exit(4);
        }
        Ok(AuthReadiness::Locked(msg)) => {
            eprintln!("{msg}");
            std::process::exit(3);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
}

async fn auth_readiness_from_client(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
) -> Result<AuthReadiness, String> {
    let local_auth = client
        .local_auth_status(target_uid)
        .await
        .map_err(|e| format!("Could not read MyKey local authentication status: {e}"))?;

    if !local_auth.enabled {
        return Ok(AuthReadiness::Ignore(
            "MyKey local authentication is not enabled. Run: mykey-pin set".to_string(),
        ));
    }
    if local_auth.primary_method != "pin" {
        return Err(format!(
            "MyKey local authentication is configured for '{}' but this build only supports the PIN backend so far.",
            local_auth.primary_method
        ));
    }

    let status = client
        .pin_status(target_uid)
        .await
        .map_err(|e| format!("Could not read MyKey PIN status: {e}"))?;

    if !status.is_set {
        return Ok(AuthReadiness::Ignore(
            "MyKey local authentication is not configured. Run: mykey-pin set".to_string(),
        ));
    }
    if status.cooldown_remaining_secs > 0 {
        return Ok(AuthReadiness::Locked(format!(
            "MyKey PIN locked. Try again in {} seconds.",
            status.cooldown_remaining_secs
        )));
    }

    Ok(AuthReadiness::Ready)
}

async fn run_enable() {
    ensure_root("enable");

    let changed = match pam_integration::enable_targets(pam_integration::BASE_TARGETS) {
        Ok(changed) => changed,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    if changed.is_empty() {
        println!("MyKey PAM integration is already enabled for supported targets.");
    } else {
        println!("Enabled MyKey PAM integration for: {}", changed.join(", "));
    }

    let target_uid = preferred_target_uid();
    match local_auth_summary(target_uid).await {
        Ok(summary) => println!("MyKey local auth: {summary}"),
        Err(e) => println!("MyKey local auth: daemon unavailable ({e})"),
    }

    println!("If MyKey local auth is not configured yet, PAM will fall through until you run: mykey-pin set");
    maybe_offer_login_setup();
}

fn run_disable() {
    ensure_root("disable");

    match pam_integration::disable_targets(pam_integration::BASE_TARGETS) {
        Ok(changed) if changed.is_empty() => {
            println!("MyKey PAM integration is already disabled for supported targets.");
        }
        Ok(changed) => {
            println!("Disabled MyKey PAM integration for: {}", changed.join(", "));
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }

    if is_interactive_terminal() {
        println!();
        run_logout();
    } else {
        println!("Run: sudo mykey-auth logout");
    }
}

async fn run_biometrics() {
    ensure_root("biometrics");
    let target_uid = preferred_target_uid();
    let system_username = preferred_target_username().unwrap_or_else(|| target_uid.to_string());
    biometrics::run(target_uid, &system_username).await;
}

fn run_login() {
    ensure_root("login");

    let inspections = match pam_integration::inspect_targets(pam_integration::LOGIN_TARGETS) {
        Ok(inspections) => inspections,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let detected: Vec<_> = inspections
        .iter()
        .copied()
        .filter(|inspection| inspection.is_present())
        .collect();
    if detected.is_empty() {
        println!("No supported login or unlock PAM targets were detected on this system.");
        return;
    }

    let selectable: Vec<_> = detected
        .iter()
        .copied()
        .filter(|inspection| inspection.state == pam_integration::PamTargetState::Disabled)
        .collect();

    if selectable.is_empty() {
        println!("No additional login or unlock PAM targets are ready for MyKey setup.");
        print_non_selectable_login_notes(&detected);
        return;
    }

    println!("Detected login and unlock PAM targets:");
    print_target_table(&detected);

    let selected = match prompt_target_selection(
        &selectable,
        "Select the login or unlock targets MyKey should manage",
        true,
    ) {
        Ok(selected) => selected,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    if selected.is_empty() {
        println!("Login management unchanged.");
        return;
    }

    match pam_integration::enable_targets(&selected) {
        Ok(changed) if changed.is_empty() => {
            println!("Login management already enabled for the selected targets.")
        }
        Ok(changed) => println!("Enabled MyKey login management for: {}", changed.join(", ")),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn run_logout() {
    ensure_root("logout");

    let inspections = match pam_integration::inspect_targets(pam_integration::LOGIN_TARGETS) {
        Ok(inspections) => inspections,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let enabled: Vec<_> = inspections
        .iter()
        .copied()
        .filter(|inspection| inspection.state == pam_integration::PamTargetState::Enabled)
        .collect();

    if enabled.is_empty() {
        println!("No MyKey-managed login or unlock PAM targets are enabled.");
        print_non_selectable_login_notes(&inspections);
        return;
    }

    println!("MyKey currently manages these login and unlock PAM targets:");
    print_target_table(&enabled);

    let selected = match prompt_target_selection(
        &enabled,
        "Select the login or unlock targets MyKey should stop managing",
        true,
    ) {
        Ok(selected) => selected,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    if selected.is_empty() {
        println!("Login management unchanged.");
        return;
    }

    match pam_integration::disable_targets(&selected) {
        Ok(changed) if changed.is_empty() => {
            println!("Login management already disabled for the selected targets.")
        }
        Ok(changed) => println!(
            "Disabled MyKey login management for: {}",
            changed.join(", ")
        ),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

async fn run_status() {
    let target_uid = preferred_target_uid();
    match local_auth_summary(target_uid).await {
        Ok(summary) => println!("MyKey local auth: {summary}"),
        Err(e) => println!("MyKey local auth: daemon unavailable ({e})"),
    }

    let base_targets = match pam_integration::inspect_targets(pam_integration::BASE_TARGETS) {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let login_targets = match pam_integration::inspect_targets(pam_integration::LOGIN_TARGETS) {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    println!("Base PAM integration: {}", overall_pam_state(&base_targets));
    for inspection in base_targets {
        println!(
            "  - {} ({}): {}",
            inspection.target.name,
            inspection.display_path(),
            inspection.state.label()
        );
    }

    println!(
        "Login PAM integration: {}",
        overall_pam_state(&login_targets)
    );
    for inspection in login_targets {
        println!(
            "  - {} ({}): {}",
            inspection.target.name,
            inspection.display_path(),
            inspection.state.label()
        );
    }
}

async fn local_auth_summary(target_uid: u32) -> Result<String, String> {
    let client = daemon_client::DaemonClient::connect().await?;
    let local_auth = client.local_auth_status(target_uid).await?;
    let pin_status = client.pin_status(target_uid).await?;
    client.disconnect().await;

    if !local_auth.enabled || !pin_status.is_set {
        return Ok("unconfigured".to_string());
    }

    if local_auth.primary_method == "pin" {
        if pin_status.cooldown_remaining_secs > 0 {
            return Ok(format!(
                "configured (pin, locked {}s)",
                pin_status.cooldown_remaining_secs
            ));
        }
        return Ok("configured (pin)".to_string());
    }

    if let Some(backend) = local_auth.biometric_backend {
        if local_auth.pin_fallback_enabled {
            return Ok(format!("configured ({} -> pin)", backend));
        }
        return Ok(format!("configured ({backend})"));
    }

    Ok(format!("configured ({})", local_auth.primary_method))
}

fn overall_pam_state(targets: &[pam_integration::PamTargetInspection]) -> &'static str {
    let mut saw_present = false;
    let mut saw_enabled = false;
    let mut saw_non_enabled = false;

    for inspection in targets {
        match inspection.state {
            pam_integration::PamTargetState::Manual
            | pam_integration::PamTargetState::BrokenManagedBlock => return "attention",
            pam_integration::PamTargetState::Absent => {}
            pam_integration::PamTargetState::Enabled => {
                saw_present = true;
                saw_enabled = true;
            }
            pam_integration::PamTargetState::Disabled => {
                saw_present = true;
                saw_non_enabled = true;
            }
        }
    }

    if !saw_present || !saw_enabled {
        "disabled"
    } else if saw_non_enabled {
        "partial"
    } else {
        "enabled"
    }
}

fn maybe_offer_login_setup() {
    if !is_interactive_terminal() {
        println!("Run: sudo mykey-auth login");
        return;
    }

    println!();
    match prompt_yes_no(
        "Would you like to configure MyKey login management now? [y/N]: ",
        false,
    ) {
        Ok(true) => run_login(),
        Ok(false) => println!("Run: sudo mykey-auth login"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn print_non_selectable_login_notes(inspections: &[pam_integration::PamTargetInspection]) {
    let notes: Vec<_> = inspections
        .iter()
        .copied()
        .filter(|inspection| {
            matches!(
                inspection.state,
                pam_integration::PamTargetState::Manual
                    | pam_integration::PamTargetState::BrokenManagedBlock
            )
        })
        .collect();
    if notes.is_empty() {
        return;
    }

    println!("Attention required for these login targets:");
    for inspection in notes {
        println!(
            "  - {} ({}): {}",
            inspection.target.name,
            inspection.display_path(),
            inspection.state.label()
        );
    }
}

fn print_target_table(inspections: &[pam_integration::PamTargetInspection]) {
    for (idx, inspection) in inspections.iter().enumerate() {
        println!(
            "  {}. {} — {} ({})",
            idx + 1,
            inspection.target.name,
            inspection.target.description,
            inspection.state.label()
        );
    }
}

fn prompt_target_selection(
    inspections: &[pam_integration::PamTargetInspection],
    prompt: &str,
    allow_none: bool,
) -> Result<Vec<pam_integration::PamTarget>, String> {
    if !is_interactive_terminal() {
        return Err("This command requires an interactive terminal.".to_string());
    }

    println!("{prompt}");
    println!("Enter numbers separated by commas, 'all', or 'none'.");
    loop {
        print!("Selection: ");
        io::stdout()
            .flush()
            .map_err(|e| format!("Could not flush stdout: {e}"))?;

        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Could not read selection: {e}"))?;
        let input = line.trim().to_ascii_lowercase();

        if input.is_empty() || input == "none" {
            if allow_none {
                return Ok(Vec::new());
            }
            println!("A selection is required.");
            continue;
        }
        if input == "all" {
            return Ok(inspections
                .iter()
                .map(|inspection| inspection.target)
                .collect());
        }

        let mut selected = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut valid = true;
        for token in input.split(',') {
            let token = token.trim();
            let idx = match token.parse::<usize>() {
                Ok(value) if value >= 1 && value <= inspections.len() => value - 1,
                _ => {
                    valid = false;
                    break;
                }
            };
            if seen.insert(idx) {
                selected.push(inspections[idx].target);
            }
        }

        if valid {
            return Ok(selected);
        }

        println!("Invalid selection. Use item numbers, 'all', or 'none'.");
    }
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool, String> {
    if !is_interactive_terminal() {
        return Ok(default);
    }

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

fn is_interactive_terminal() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
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

    let uid = preferred_target_uid();
    unsafe {
        let passwd = libc::getpwuid(uid);
        if passwd.is_null() || (*passwd).pw_name.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr((*passwd).pw_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

fn ensure_root(command: &str) {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "mykey-auth {command} modifies /etc/pam.d and must be run as root.\nRun: sudo mykey-auth {command}"
        );
        std::process::exit(1);
    }
}

fn read_pin_from_stdin() -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    Ok(Zeroizing::new(buf))
}

#[cfg(test)]
mod tests {
    use super::{parse_args, Command};

    #[test]
    fn parse_authenticate_args_accepts_uid_and_pin_stdin() {
        let args = vec![
            "mykey-auth".to_string(),
            "authenticate".to_string(),
            "--uid".to_string(),
            "1000".to_string(),
            "--pin-stdin".to_string(),
        ];

        let parsed = parse_args(&args).expect("arguments should parse");
        match parsed {
            Command::Authenticate {
                target_uid,
                pin_from_stdin,
            } => {
                assert_eq!(target_uid, 1000);
                assert!(pin_from_stdin);
            }
            _ => panic!("expected authenticate command"),
        }
    }

    #[test]
    fn parse_enable_command() {
        let args = vec!["mykey-auth".to_string(), "enable".to_string()];
        assert!(matches!(parse_args(&args), Ok(Command::Enable)));
    }

    #[test]
    fn parse_biometrics_command() {
        let args = vec!["mykey-auth".to_string(), "biometrics".to_string()];
        assert!(matches!(parse_args(&args), Ok(Command::Biometrics)));
    }

    #[test]
    fn parse_login_command() {
        let args = vec!["mykey-auth".to_string(), "login".to_string()];
        assert!(matches!(parse_args(&args), Ok(Command::Login)));
    }

    #[test]
    fn parse_logout_command() {
        let args = vec!["mykey-auth".to_string(), "logout".to_string()];
        assert!(matches!(parse_args(&args), Ok(Command::Logout)));
    }

    #[test]
    fn parse_status_command() {
        let args = vec!["mykey-auth".to_string(), "status".to_string()];
        assert!(matches!(parse_args(&args), Ok(Command::Status)));
    }
}
