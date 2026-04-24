#[path = "../auth_client.rs"]
mod auth_client;

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let target_uid = parse_args(&args).unwrap_or_else(|msg| {
        eprintln!("{msg}");
        print_usage();
        std::process::exit(2);
    });

    if let Err(e) = ensure_uid_access(target_uid) {
        eprintln!("{e}");
        std::process::exit(2);
    }

    let username = match auth_client::uid_to_username(target_uid) {
        Some(username) => username,
        None => {
            eprintln!("Could not resolve a Linux account for uid={target_uid}.");
            std::process::exit(2);
        }
    };

    match auth_client::authenticate_user(&username) {
        Ok(()) => std::process::exit(0),
        Err(code) if auth_client::is_auth_failure(code) => {
            eprintln!("Security-key authentication failed.");
            std::process::exit(1);
        }
        Err(code) => {
            eprintln!(
                "Security-key authentication failed through PAM service '{}': {}",
                auth_client::PAM_SERVICE,
                code
            );
            std::process::exit(2);
        }
    }
}

fn parse_args(args: &[String]) -> Result<u32, String> {
    if args.len() != 4 || args.get(1).map(|s| s.as_str()) != Some("verify") {
        return Err("Invalid arguments.".to_string());
    }
    if args.get(2).map(|s| s.as_str()) != Some("--uid") {
        return Err("Missing required --uid argument.".to_string());
    }

    args[3]
        .parse::<u32>()
        .map_err(|_| format!("Invalid uid: {}", args[3]))
}

fn print_usage() {
    eprintln!("Usage: mykey-security-key-auth verify --uid <uid>");
}

fn ensure_uid_access(target_uid: u32) -> Result<(), String> {
    let real_uid = unsafe { libc::getuid() as u32 };
    if real_uid == 0 || real_uid == target_uid {
        Ok(())
    } else {
        Err(format!(
            "Real uid {real_uid} may not request security-key auth for uid={target_uid}"
        ))
    }
}
