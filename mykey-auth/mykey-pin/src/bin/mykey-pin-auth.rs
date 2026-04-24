// mykey-pin-auth — trusted PAM helper for MyKey PIN verification.
//
// This helper is intentionally narrow. It exists so PAM-hosted authentication
// can call into mykey-daemon through a trusted MyKey executable rather than
// from host processes such as sudo, login, or a display manager.

#[path = "../auth_daemon_client.rs"]
mod daemon_client;

use std::io::Read;

use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let (command, target_uid) = parse_args(&args).unwrap_or_else(|msg| {
        eprintln!("{msg}");
        print_usage();
        std::process::exit(2);
    });

    match command {
        Command::Verify => run_verify(target_uid).await,
    }
}

#[derive(Debug, Clone, Copy)]
enum Command {
    Verify,
}

fn parse_args(args: &[String]) -> Result<(Command, u32), String> {
    if args.len() != 4 || args.get(1).map(|s| s.as_str()) != Some("verify") {
        return Err("Invalid arguments.".to_string());
    }
    if args.get(2).map(|s| s.as_str()) != Some("--uid") {
        return Err("Missing required --uid argument.".to_string());
    }

    let uid = args[3]
        .parse::<u32>()
        .map_err(|_| format!("Invalid uid: {}", args[3]))?;
    Ok((Command::Verify, uid))
}

fn print_usage() {
    eprintln!("Usage: mykey-pin-auth verify --uid <uid>");
    eprintln!("Reads the PIN from standard input and verifies it through mykey-daemon.");
}

async fn run_verify(target_uid: u32) {
    let client = match daemon_client::DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(2);
        }
    };

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
        eprintln!("No MyKey PIN is set. Run: mykey-pin set");
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

    match result {
        Ok(true) => {
            client.disconnect().await;
            std::process::exit(0);
        }
        Ok(false) => {
            let status = client.pin_status(target_uid).await;
            client.disconnect().await;
            match status {
                Ok(status) if status.cooldown_remaining_secs > 0 => {
                    eprintln!(
                        "Incorrect MyKey PIN.\nMyKey PIN locked. Try again in {} seconds.",
                        status.cooldown_remaining_secs
                    );
                    std::process::exit(3);
                }
                Ok(_) => std::process::exit(1),
                Err(e) => {
                    eprintln!("Could not read MyKey PIN status: {e}");
                    std::process::exit(2);
                }
            }
        }
        Err(e) => {
            client.disconnect().await;
            eprintln!("MyKey PIN verification failed: {e}");
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
