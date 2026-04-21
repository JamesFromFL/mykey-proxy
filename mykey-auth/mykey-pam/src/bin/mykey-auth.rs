// mykey-auth — unified local authentication helper for MyKey.
//
// Phase A behavior:
//   - acts as the trusted helper behind pam_mykey.so
//   - authenticates using the existing MyKey PIN backend
//   - keeps room for future biometric-first auth before PIN fallback

#[path = "../daemon_client.rs"]
mod daemon_client;

use std::io::Read;

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
    }
}

#[derive(Debug, Clone, Copy)]
enum Command {
    Authenticate {
        target_uid: u32,
        pin_from_stdin: bool,
    },
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.len() < 4 || args.get(1).map(|s| s.as_str()) != Some("authenticate") {
        return Err("Invalid arguments.".to_string());
    }

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
                pin_from_stdin = true;
                idx += 1;
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    let target_uid = target_uid.ok_or_else(|| "Missing required --uid argument.".to_string())?;
    Ok(Command::Authenticate {
        target_uid,
        pin_from_stdin,
    })
}

fn print_usage() {
    eprintln!("Usage: mykey-auth authenticate --uid <uid> --pin-stdin");
    eprintln!("Phase A uses the existing MyKey PIN backend for unified local auth.");
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

    let local_auth = match client.local_auth_status(target_uid).await {
        Ok(status) => status,
        Err(e) => {
            client.disconnect().await;
            eprintln!("Could not read MyKey local authentication status: {e}");
            std::process::exit(2);
        }
    };
    if !local_auth.enabled {
        client.disconnect().await;
        eprintln!("MyKey local authentication is not enabled. Run: mykey-pin set");
        std::process::exit(4);
    }
    if local_auth.primary_method != "pin" {
        client.disconnect().await;
        eprintln!(
            "MyKey local authentication is configured for '{}' but this build only supports the PIN backend so far.",
            local_auth.primary_method
        );
        std::process::exit(2);
    }

    let status = match client.pin_status(target_uid).await {
        Ok(status) => status,
        Err(e) => {
            client.disconnect().await;
            eprintln!("Could not read MyKey PIN status: {e}");
            std::process::exit(2);
        }
    };

    if !status.is_set {
        client.disconnect().await;
        eprintln!("MyKey local authentication is not configured. Run: mykey-pin set");
        std::process::exit(4);
    }
    if status.cooldown_remaining_secs > 0 {
        client.disconnect().await;
        eprintln!(
            "MyKey PIN locked. Try again in {} seconds.",
            status.cooldown_remaining_secs
        );
        std::process::exit(3);
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
        }
    }
}
