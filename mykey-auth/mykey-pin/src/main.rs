// main.rs — CLI entry point for MyKey PIN management.
//
// Usage:
//   mykey-pin set      Set or update your MyKey PIN
//   mykey-pin change   Change your MyKey PIN
//   mykey-pin reset    Reset PIN using your Linux password
//   mykey-pin status   Show PIN and lockout status

mod daemon_client;

use zeroize::Zeroizing;

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
        require_strong_auth(
            &client,
            "First-time PIN enrollment requires verifying your Linux password or fingerprint.",
        )
        .await;
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
    require_strong_auth(
        &client,
        "Resetting PIN requires verifying your Linux password or fingerprint.",
    )
    .await;

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

async fn require_strong_auth(
    client: &daemon_client::DaemonClient,
    intro: &str,
) {
    println!("{intro}");
    match client.confirm_user_presence().await {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("Authentication failed.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Could not verify your identity: {e}");
            std::process::exit(1);
        }
    }
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() as u32 }
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
        assert_eq!(validate_new_pin("123"), Err("PIN must be at least 4 digits."));
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
