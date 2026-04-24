#[path = "../elevated_daemon_client.rs"]
mod daemon_client;
#[path = "../password_verifier.rs"]
mod password_verifier;

use std::io::Read;

use zeroize::Zeroizing;

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
        ElevatedCommand::Status { target_uid } => run_status(target_uid).await,
        ElevatedCommand::Verify { target_uid, purpose } => run_verify(target_uid, purpose).await,
    }
}

async fn run_status(target_uid: u32) {
    if let Err(e) = ensure_uid_access(target_uid) {
        eprintln!("{e}");
        std::process::exit(2);
    }

    let daemon = match daemon_client::DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(2);
        }
    };

    match daemon.elevated_auth_status(target_uid).await {
        Ok(status) if status.retry_after_secs > 0 => {
            daemon.disconnect().await;
            eprintln!(
                "Elevated MyKey password auth is rate-limited. Try again in {} seconds.",
                status.retry_after_secs
            );
            std::process::exit(3);
        }
        Ok(_) => {
            daemon.disconnect().await;
            std::process::exit(0);
        }
        Err(e) => {
            daemon.disconnect().await;
            eprintln!("Could not read elevated auth status: {e}");
            std::process::exit(2);
        }
    }
}

async fn run_verify(target_uid: u32, purpose: String) {

    if let Err(e) = ensure_uid_access(target_uid) {
        eprintln!("{e}");
        std::process::exit(2);
    }

    let password = match read_password_from_stdin() {
        Ok(password) if !password.is_empty() => password,
        Ok(_) => {
            eprintln!("No Linux password data was provided on standard input.");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("Failed to read Linux password from standard input: {e}");
            std::process::exit(2);
        }
    };

    let username = match password_verifier::uid_to_username(target_uid) {
        Some(username) => username,
        None => {
            eprintln!("Could not resolve a Linux account for uid={target_uid}.");
            std::process::exit(2);
        }
    };

    let daemon = match daemon_client::DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(2);
        }
    };

    match daemon.elevated_auth_status(target_uid).await {
        Ok(status) if status.retry_after_secs > 0 => {
            daemon.disconnect().await;
            eprintln!(
                "Elevated MyKey password auth is rate-limited. Try again in {} seconds.",
                status.retry_after_secs
            );
            std::process::exit(3);
        }
        Ok(_) => {}
        Err(e) => {
            daemon.disconnect().await;
            eprintln!("Could not read elevated auth status: {e}");
            std::process::exit(2);
        }
    }

    match password_verifier::verify_password(&username, &password) {
        Ok(()) => {
            let result = daemon.grant_elevated_auth(target_uid, &purpose).await;
            daemon.disconnect().await;
            match result {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("Could not grant elevated MyKey auth: {e}");
                    std::process::exit(2);
                }
            }
        }
        Err(code) if password_verifier::is_auth_failure(code) => {
            let status = daemon.record_elevated_auth_failure(target_uid).await;
            daemon.disconnect().await;
            match status {
                Ok(status) if status.retry_after_secs > 0 => {
                    eprintln!(
                        "Linux password verification failed. Retry in {} seconds.",
                        status.retry_after_secs
                    );
                }
                Ok(_) => eprintln!("Linux password verification failed."),
                Err(e) => eprintln!("Linux password verification failed ({e})."),
            }
            std::process::exit(1);
        }
        Err(code) => {
            daemon.disconnect().await;
            eprintln!(
                "Elevated password verification failed through PAM service '{}': {}",
                password_verifier::PAM_SERVICE,
                code
            );
            std::process::exit(2);
        }
    }
}

enum ElevatedCommand {
    Status { target_uid: u32 },
    Verify { target_uid: u32, purpose: String },
}

fn parse_args(args: &[String]) -> Result<ElevatedCommand, String> {
    match args.get(1).map(|s| s.as_str()) {
        Some("status") => parse_status_args(args),
        Some("verify") => parse_verify_args(args),
        _ => Err("Invalid arguments.".to_string()),
    }
}

fn parse_status_args(args: &[String]) -> Result<ElevatedCommand, String> {
    if args.len() != 4 || args.get(2).map(|s| s.as_str()) != Some("--uid") {
        return Err("Usage: mykey-elevated-auth status --uid <uid>".to_string());
    }

    let target_uid = args[3]
        .parse::<u32>()
        .map_err(|_| format!("Invalid uid: {}", args[3]))?;
    Ok(ElevatedCommand::Status { target_uid })
}

fn parse_verify_args(args: &[String]) -> Result<ElevatedCommand, String> {
    if args.len() != 6 || args.get(2).map(|s| s.as_str()) != Some("--uid") {
        return Err("Missing required --uid argument.".to_string());
    }
    if args.get(4).map(|s| s.as_str()) != Some("--purpose") {
        return Err("Missing required --purpose argument.".to_string());
    }

    let target_uid = args[3]
        .parse::<u32>()
        .map_err(|_| format!("Invalid uid: {}", args[3]))?;
    let purpose = args[5].clone();
    match purpose.as_str() {
        "pin_enroll" | "pin_reset" | "biometric_manage" | "security_key_manage" => {
            Ok(ElevatedCommand::Verify { target_uid, purpose })
        }
        _ => Err(format!("Unsupported purpose: {purpose}")),
    }
}

fn print_usage() {
    eprintln!("Usage: mykey-elevated-auth status --uid <uid>");
    eprintln!("Usage: mykey-elevated-auth verify --uid <uid> --purpose <purpose>");
    eprintln!("Purposes: pin_enroll | pin_reset | biometric_manage | security_key_manage");
    eprintln!("Reads the Linux password from standard input.");
}

fn ensure_uid_access(target_uid: u32) -> Result<(), String> {
    let real_uid = unsafe { libc::getuid() as u32 };
    if real_uid == 0 || real_uid == target_uid {
        Ok(())
    } else {
        Err(format!(
            "Real uid {real_uid} may not request elevated auth for uid={target_uid}"
        ))
    }
}

fn read_password_from_stdin() -> Result<Zeroizing<String>, std::io::Error> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    let text = String::from_utf8(buf).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "password is not valid UTF-8",
        )
    })?;
    Ok(Zeroizing::new(text))
}
