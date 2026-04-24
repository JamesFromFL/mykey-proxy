// main.rs — CLI entry point for MyKey PIN management.
//
// Usage:
//   mykey-pin set      Set or update your MyKey PIN
//   mykey-pin change   Change your MyKey PIN
//   mykey-pin reset    Reset PIN using your Linux password
//   mykey-pin status   Show PIN and lockout status

#[path = "cli_daemon_client.rs"]
mod daemon_client;

use std::io::Write;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

const ELEVATED_AUTH_HELPER_CANDIDATES: &[&str] = &[
    "/usr/local/bin/mykey-elevated-auth",
    "/usr/bin/mykey-elevated-auth",
];

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("set") => run_set().await,
        Some("change") => run_change().await,
        Some("reset") => run_reset().await,
        Some("status") => run_status().await,
        _ => print_usage(),
    }
}

fn print_usage() {
    println!("mykey-pin set      Set or update your MyKey PIN");
    println!("mykey-pin change   Change your MyKey PIN");
    println!("mykey-pin reset    Reset PIN using your Linux password");
    println!("mykey-pin status   Show PIN and lockout status");
}

fn validate_new_pin(pin: &str) -> Result<(), &'static str> {
    let len = pin.len();
    if len < 4 {
        return Err("PIN must be at least 4 digits.");
    }
    if len > 12 {
        return Err("PIN must be no more than 12 digits.");
    }
    if !pin.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return Err("PIN must contain digits only.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// set
// ---------------------------------------------------------------------------

async fn run_set() {
    let uid = current_uid();
    let client = connect_client().await;
    let status = match client.pin_status(uid).await {
        Ok(status) => status,
        Err(e) => {
            eprintln!("Could not read MyKey PIN status: {e}");
            client.disconnect().await;
            std::process::exit(1);
        }
    };

    if status.is_set {
        set_existing_pin(&client, uid).await;
    } else {
        require_elevated_password(
            uid,
            "pin_enroll",
            "First-time PIN enrollment requires verifying your Linux account password.",
        );
        enroll_new_pin(&client, uid).await;
    }

    client.disconnect().await;
}

// ---------------------------------------------------------------------------
// change
// ---------------------------------------------------------------------------

async fn run_change() {
    let uid = current_uid();
    let client = connect_client().await;
    let status = match client.pin_status(uid).await {
        Ok(status) => status,
        Err(e) => {
            eprintln!("Could not read MyKey PIN status: {e}");
            client.disconnect().await;
            std::process::exit(1);
        }
    };

    if !status.is_set {
        eprintln!("No MyKey PIN is set. Use 'mykey-pin set' first.");
        client.disconnect().await;
        std::process::exit(1);
    }

    set_existing_pin(&client, uid).await;
    client.disconnect().await;
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

async fn run_reset() {
    let uid = current_uid();
    let client = connect_client().await;
    require_elevated_password(
        uid,
        "pin_reset",
        "Resetting PIN requires verifying your Linux account password.",
    );

    if let Err(e) = client.pin_reset(uid).await {
        client.disconnect().await;
        eprintln!("Failed to reset MyKey PIN: {e}");
        std::process::exit(1);
    }
    client.disconnect().await;
    println!("✓ MyKey PIN reset. Run mykey-pin set to create a new PIN.");
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

async fn run_status() {
    let uid = current_uid();
    let client = connect_client().await;
    let status = match client.pin_status(uid).await {
        Ok(status) => status,
        Err(e) => {
            client.disconnect().await;
            eprintln!("Could not read MyKey PIN status: {e}");
            std::process::exit(1);
        }
    };
    client.disconnect().await;

    println!("MyKey PIN status:");
    println!("  PIN set:    {}", if status.is_set { "yes" } else { "no" });
    if status.cooldown_remaining_secs > 0 {
        println!(
            "  Locked out: yes ({} seconds remaining)",
            status.cooldown_remaining_secs
        );
    } else {
        println!("  Locked out: no");
    }
    println!("  Failed attempts: {}", status.failed_sessions);
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async fn connect_client() -> daemon_client::DaemonClient {
    match daemon_client::DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(1);
        }
    }
}

fn require_elevated_password(uid: u32, purpose: &str, intro: &str) {
    println!("{intro}");
    let password = match prompt_linux_password("Linux account password: ") {
        Some(password) => password,
        None => {
            eprintln!("Failed to read Linux password.");
            std::process::exit(1);
        }
    };

    match run_elevated_auth_helper(uid, purpose, password.as_bytes()) {
        HelperAuthResult::Success => {}
        HelperAuthResult::AuthFailed(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
        HelperAuthResult::RateLimited(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
        HelperAuthResult::Error(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

fn current_uid() -> u32 {
    if unsafe { libc::geteuid() } == 0 {
        std::env::var("SUDO_UID")
            .ok()
            .and_then(|uid| uid.parse::<u32>().ok())
            .unwrap_or_else(|| unsafe { libc::getuid() })
    } else {
        unsafe { libc::getuid() }
    }
}

async fn enroll_new_pin(client: &daemon_client::DaemonClient, uid: u32) {
    let new_pin = match prompt_pin("Enter new MyKey PIN: ") {
        Some(pin) => pin,
        None => {
            eprintln!("Failed to read PIN.");
            std::process::exit(1);
        }
    };
    let confirm = match prompt_pin("Confirm new MyKey PIN: ") {
        Some(pin) => pin,
        None => {
            eprintln!("Failed to read PIN confirmation.");
            std::process::exit(1);
        }
    };

    if new_pin != confirm {
        eprintln!("PINs do not match.");
        std::process::exit(1);
    }

    if let Err(msg) = validate_new_pin(new_pin.as_str()) {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    if let Err(e) = client.pin_enroll(uid, new_pin.as_bytes()).await {
        eprintln!("Failed to enroll MyKey PIN: {e}");
        std::process::exit(1);
    }

    println!("✓ MyKey PIN set successfully.");
}

async fn set_existing_pin(client: &daemon_client::DaemonClient, uid: u32) {
    let current_pin = match prompt_pin("Current MyKey PIN: ") {
        Some(pin) => pin,
        None => {
            eprintln!("Failed to read current PIN.");
            std::process::exit(1);
        }
    };
    let new_pin = match prompt_pin("Enter new MyKey PIN: ") {
        Some(pin) => pin,
        None => {
            eprintln!("Failed to read PIN.");
            std::process::exit(1);
        }
    };
    let confirm = match prompt_pin("Confirm new MyKey PIN: ") {
        Some(pin) => pin,
        None => {
            eprintln!("Failed to read PIN confirmation.");
            std::process::exit(1);
        }
    };

    if new_pin != confirm {
        eprintln!("PINs do not match.");
        std::process::exit(1);
    }

    if let Err(msg) = validate_new_pin(new_pin.as_str()) {
        eprintln!("{msg}");
        std::process::exit(1);
    }

    match client
        .pin_change(uid, current_pin.as_bytes(), new_pin.as_bytes())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("Current PIN verification failed.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to change MyKey PIN: {e}");
            std::process::exit(1);
        }
    }

    println!("✓ MyKey PIN set successfully.");
}

/// Prompt for a PIN with no terminal echo.  Returns `None` on I/O error.
fn prompt_pin(prompt: &str) -> Option<Zeroizing<String>> {
    rpassword::prompt_password(prompt).ok().map(Zeroizing::new)
}

fn prompt_linux_password(prompt: &str) -> Option<Zeroizing<String>> {
    rpassword::prompt_password(prompt).ok().map(Zeroizing::new)
}

enum HelperAuthResult {
    Success,
    AuthFailed(String),
    RateLimited(String),
    Error(String),
}

fn run_elevated_auth_helper(uid: u32, purpose: &str, password: &[u8]) -> HelperAuthResult {
    let helper_path = match resolve_elevated_auth_helper_path() {
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
            "Linux password verification failed.",
        )),
        Some(3) => HelperAuthResult::RateLimited(non_empty_message(
            stderr,
            "Elevated MyKey password auth is temporarily rate-limited.",
        )),
        Some(2) => HelperAuthResult::Error(non_empty_message(
            stderr,
            "Elevated MyKey password verification failed.",
        )),
        Some(code) => HelperAuthResult::Error(format!(
            "mykey-elevated-auth exited unexpectedly with status {code}"
        )),
        None => HelperAuthResult::Error(
            "mykey-elevated-auth terminated without an exit status".to_string(),
        ),
    }
}

fn resolve_elevated_auth_helper_path() -> Option<&'static str> {
    ELEVATED_AUTH_HELPER_CANDIDATES
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).is_file())
}

fn non_empty_message(message: String, fallback: &str) -> String {
    if message.is_empty() {
        fallback.to_string()
    } else {
        message
    }
}

#[cfg(test)]
mod tests {
    use super::validate_new_pin;

    #[test]
    fn pin_policy_accepts_numeric_lengths_in_range() {
        assert!(validate_new_pin("1234").is_ok());
        assert!(validate_new_pin("123456789012").is_ok());
    }

    #[test]
    fn pin_policy_rejects_short_long_or_non_numeric_values() {
        assert_eq!(validate_new_pin(""), Err("PIN must be at least 4 digits."));
        assert_eq!(
            validate_new_pin("123"),
            Err("PIN must be at least 4 digits.")
        );
        assert_eq!(
            validate_new_pin("1234567890123"),
            Err("PIN must be no more than 12 digits.")
        );
        assert_eq!(
            validate_new_pin("12ab"),
            Err("PIN must contain digits only.")
        );
        assert_eq!(
            validate_new_pin("12 4"),
            Err("PIN must contain digits only.")
        );
    }
}
