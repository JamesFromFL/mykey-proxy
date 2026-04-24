// mykey-auth — unified local authentication helper for MyKey.
//
// Runtime behavior:
//   - acts as the trusted helper behind pam_mykey.so
//   - asks the daemon for the effective local-auth policy
//   - keeps normal Linux password fallback inside MyKey when no PIN is configured
//   - performs biometric-first auth when enabled, then falls back to MyKey PIN
//   - keeps PIN lockout separate from biometric failures

#[path = "../biometrics.rs"]
mod biometrics;
#[path = "../runtime_daemon_client.rs"]
mod daemon_client;
#[path = "../pam_integration.rs"]
mod pam_integration;
#[path = "../password_verifier.rs"]
mod password_verifier;
#[path = "../security_keys.rs"]
mod security_keys;

use std::io::Read;
use std::io::{self, Write};

use zeroize::Zeroizing;

const EXIT_AUTH_FAILED: i32 = 1;
const EXIT_INTERNAL_ERROR: i32 = 2;
const EXIT_LOCKED: i32 = 3;
const EXIT_IGNORE: i32 = 4;
const EXIT_PIN_FALLBACK_REQUIRED: i32 = 5;
const SECURITY_KEY_PAM_SERVICE_CANDIDATES: &[&str] = &["/etc/pam.d/mykey-security-key-auth"];
const PAM_U2F_CFG_CANDIDATES: &[&str] = &["/usr/bin/pamu2fcfg", "/usr/local/bin/pamu2fcfg"];
const PAM_U2F_MODULE_CANDIDATES: &[&str] = &[
    "/usr/lib/security/pam_u2f.so",
    "/usr/lib64/security/pam_u2f.so",
];

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
        Command::Authenticate { target_uid, input } => run_authenticate(target_uid, input).await,
        Command::Preflight { target_uid } => run_preflight(target_uid).await,
        Command::Setup => run_setup().await,
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
        input: AuthenticateInput,
    },
    Preflight {
        target_uid: u32,
    },
    Setup,
    Enable,
    Disable,
    Biometrics,
    Login,
    Logout,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticateInput {
    None,
    PinFromStdin,
    PasswordFromStdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthReadiness {
    Ready(AuthMode),
    Ignore(String),
    Locked(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthMode {
    PinOnly,
    PasswordFallback,
    BiometricFirst {
        backends: Vec<String>,
        security_key_enabled: bool,
        pin_enabled: bool,
        attempt_limit: u8,
    },
    SecurityKeyFirst {
        pin_enabled: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthenticateResult {
    Success,
    AuthFailed(String),
    PinFallbackRequired(String),
    NotConfigured(String),
    Locked(String),
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    match args.get(1).map(|s| s.as_str()) {
        Some("authenticate") => parse_authenticate_command(args),
        Some("preflight") => parse_preflight_command(args),
        Some("setup") if args.len() == 2 => Ok(Command::Setup),
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

fn parse_authenticate_command(args: &[String]) -> Result<Command, String> {
    let mut target_uid = None;
    let mut input = AuthenticateInput::None;
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
                if input != AuthenticateInput::None {
                    return Err("Use only one stdin auth source for authenticate.".to_string());
                }
                input = AuthenticateInput::PinFromStdin;
                idx += 1;
            }
            "--password-stdin" => {
                if input != AuthenticateInput::None {
                    return Err("Use only one stdin auth source for authenticate.".to_string());
                }
                input = AuthenticateInput::PasswordFromStdin;
                idx += 1;
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    let target_uid = target_uid.ok_or_else(|| "Missing required --uid argument.".to_string())?;
    Ok(Command::Authenticate { target_uid, input })
}

fn parse_preflight_command(args: &[String]) -> Result<Command, String> {
    let mut target_uid = None;
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
            "--pin-stdin" | "--password-stdin" => {
                return Err("stdin auth flags are only valid for authenticate.".to_string());
            }
            other => return Err(format!("Unknown argument: {other}")),
        }
    }

    let target_uid = target_uid.ok_or_else(|| "Missing required --uid argument.".to_string())?;
    Ok(Command::Preflight { target_uid })
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  mykey-auth setup");
    eprintln!("  mykey-auth enable");
    eprintln!("  mykey-auth disable");
    eprintln!("  mykey-auth biometrics");
    eprintln!("  mykey-auth login");
    eprintln!("  mykey-auth logout");
    eprintln!("  mykey-auth status");
    eprintln!("  mykey-auth authenticate --uid <uid> [--pin-stdin|--password-stdin] (internal)");
    eprintln!("  mykey-auth preflight --uid <uid>                  (internal)");
}

async fn run_authenticate(target_uid: u32, input: AuthenticateInput) {
    let client = match daemon_client::DaemonClient::connect().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to mykey-daemon: {e}");
            std::process::exit(EXIT_INTERNAL_ERROR);
        }
    };

    let readiness = auth_readiness_from_client(&client, target_uid).await;
    let mode = match readiness {
        Ok(AuthReadiness::Ready(mode)) => mode,
        Ok(AuthReadiness::Ignore(msg)) => {
            client.disconnect().await;
            eprintln!("{msg}");
            std::process::exit(EXIT_IGNORE);
        }
        Ok(AuthReadiness::Locked(msg)) => {
            client.disconnect().await;
            eprintln!("{msg}");
            std::process::exit(EXIT_LOCKED);
        }
        Err(e) => {
            client.disconnect().await;
            eprintln!("{e}");
            std::process::exit(EXIT_INTERNAL_ERROR);
        }
    };

    let result = match input {
        AuthenticateInput::PinFromStdin => match mode {
            AuthMode::PasswordFallback => {
                Err("MyKey PIN fallback is not currently available for this account.".to_string())
            }
            _ => authenticate_with_pin_fallback(&client, target_uid).await,
        },
        AuthenticateInput::PasswordFromStdin => match mode {
            AuthMode::PasswordFallback => {
                authenticate_with_password_fallback(&client, target_uid).await
            }
            _ => Err(
                "MyKey Linux password fallback is not currently allowed for this account."
                    .to_string(),
            ),
        },
        AuthenticateInput::None => match mode {
            AuthMode::PinOnly => Ok(AuthenticateResult::PinFallbackRequired(String::new())),
            AuthMode::PasswordFallback => Ok(AuthenticateResult::PinFallbackRequired(
                "MyKey-managed Linux password fallback is required.".to_string(),
            )),
            AuthMode::BiometricFirst {
                backends,
                security_key_enabled,
                pin_enabled,
                attempt_limit,
            } => {
                authenticate_with_biometrics(
                    &client,
                    target_uid,
                    &backends,
                    security_key_enabled,
                    pin_enabled,
                    attempt_limit,
                )
                .await
            }
            AuthMode::SecurityKeyFirst { pin_enabled } => {
                authenticate_with_security_key(&client, target_uid, pin_enabled).await
            }
        },
    };
    client.disconnect().await;

    match result {
        Ok(AuthenticateResult::Success) => std::process::exit(0),
        Ok(AuthenticateResult::AuthFailed(msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            std::process::exit(EXIT_AUTH_FAILED);
        }
        Ok(AuthenticateResult::PinFallbackRequired(msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            std::process::exit(EXIT_PIN_FALLBACK_REQUIRED);
        }
        Ok(AuthenticateResult::NotConfigured(msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            std::process::exit(EXIT_IGNORE);
        }
        Ok(AuthenticateResult::Locked(msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            std::process::exit(EXIT_LOCKED);
        }
        Err(e) => {
            eprintln!("MyKey authentication failed: {e}");
            std::process::exit(EXIT_INTERNAL_ERROR);
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
        Ok(AuthReadiness::Ready(mode)) => {
            println!("{}", preflight_mode_label(&mode));
            std::process::exit(0);
        }
        Ok(AuthReadiness::Ignore(msg)) => {
            eprintln!("{msg}");
            std::process::exit(EXIT_IGNORE);
        }
        Ok(AuthReadiness::Locked(msg)) => {
            eprintln!("{msg}");
            std::process::exit(EXIT_LOCKED);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(EXIT_INTERNAL_ERROR);
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
        if local_auth.password_fallback_allowed {
            return password_fallback_readiness(client, target_uid).await;
        }
        return Ok(AuthReadiness::Ignore(
            "MyKey local authentication is not enabled. Run: mykey-pin set".to_string(),
        ));
    }

    let status = client
        .pin_status(target_uid)
        .await
        .map_err(|e| format!("Could not read MyKey PIN status: {e}"))?;

    if !status.is_set {
        if local_auth.password_fallback_allowed {
            return password_fallback_readiness(client, target_uid).await;
        }
        return Ok(AuthReadiness::Ignore(
            "MyKey local authentication is not configured. Run: mykey-pin set".to_string(),
        ));
    }

    let biometric_enabled = local_auth.has_stage("biometric");
    let security_key_enabled = local_auth.has_stage("security_key");
    let pin_enabled = local_auth.has_stage("pin");

    if biometric_enabled {
        if local_auth.biometric_backends.is_empty() {
            return Err(
                "MyKey biometric policy is active but no biometric backend is configured."
                    .to_string(),
            );
        }
        if !pin_enabled {
            return Err("MyKey biometric policy is missing the required PIN stage.".to_string());
        }

        return Ok(AuthReadiness::Ready(AuthMode::BiometricFirst {
            backends: local_auth.biometric_backends.clone(),
            security_key_enabled,
            pin_enabled,
            attempt_limit: local_auth.biometric_attempt_limit.max(1),
        }));
    }

    if security_key_enabled {
        if !pin_enabled {
            return Err("MyKey security-key policy is missing the required PIN stage.".to_string());
        }

        return Ok(AuthReadiness::Ready(AuthMode::SecurityKeyFirst {
            pin_enabled,
        }));
    }

    if pin_enabled {
        if status.cooldown_remaining_secs > 0 {
            return Ok(AuthReadiness::Locked(format!(
                "MyKey PIN locked. Try again in {} seconds.",
                status.cooldown_remaining_secs
            )));
        }

        return Ok(AuthReadiness::Ready(AuthMode::PinOnly));
    }

    Err("MyKey local authentication policy is enabled but contains no runnable auth stages."
        .to_string())
}

fn preflight_mode_label(mode: &AuthMode) -> String {
    match mode {
        AuthMode::PinOnly => "pin".to_string(),
        AuthMode::PasswordFallback => "password".to_string(),
        AuthMode::BiometricFirst { backends, .. } => {
            if backends.len() == 1 {
                format!("biometric:{}", backends[0])
            } else {
                format!("biometric-group:{}", backends.join(","))
            }
        }
        AuthMode::SecurityKeyFirst { .. } => "security_key".to_string(),
    }
}

async fn password_fallback_readiness(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
) -> Result<AuthReadiness, String> {
    let status = client
        .password_fallback_status(target_uid)
        .await
        .map_err(|e| format!("Could not read MyKey password fallback status: {e}"))?;

    if status.retry_after_secs > 0 {
        return Ok(AuthReadiness::Locked(format!(
            "MyKey Linux password fallback is rate-limited. Try again in {} seconds.",
            status.retry_after_secs
        )));
    }

    Ok(AuthReadiness::Ready(AuthMode::PasswordFallback))
}

async fn authenticate_with_pin_fallback(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
) -> Result<AuthenticateResult, String> {
    let status = client
        .pin_status(target_uid)
        .await
        .map_err(|e| format!("Could not read MyKey PIN status: {e}"))?;

    if !status.is_set {
        return Ok(AuthenticateResult::NotConfigured(
            "MyKey local authentication is not configured. Run: mykey-pin set".to_string(),
        ));
    }
    if status.cooldown_remaining_secs > 0 {
        return Ok(AuthenticateResult::Locked(format!(
            "MyKey PIN locked. Try again in {} seconds.",
            status.cooldown_remaining_secs
        )));
    }

    let pin = match read_pin_from_stdin() {
        Ok(pin) if !pin.is_empty() => pin,
        Ok(_) => {
            return Err("No PIN data was provided on standard input.".to_string());
        }
        Err(e) => {
            return Err(format!("Failed to read PIN from standard input: {e}"));
        }
    };

    let verified = client.pin_verify(target_uid, pin.as_slice()).await?;
    if verified {
        Ok(AuthenticateResult::Success)
    } else {
        Ok(AuthenticateResult::AuthFailed(
            "Incorrect MyKey PIN.".to_string(),
        ))
    }
}

async fn authenticate_with_password_fallback(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
) -> Result<AuthenticateResult, String> {
    let status = client
        .password_fallback_status(target_uid)
        .await
        .map_err(|e| format!("Could not read MyKey password fallback status: {e}"))?;

    if status.retry_after_secs > 0 {
        return Ok(AuthenticateResult::Locked(format!(
            "MyKey Linux password fallback is rate-limited. Try again in {} seconds.",
            status.retry_after_secs
        )));
    }

    let password = match read_password_from_stdin() {
        Ok(password) if !password.is_empty() => password,
        Ok(_) => return Err("No Linux password data was provided on standard input.".to_string()),
        Err(e) => {
            return Err(format!(
                "Failed to read Linux password from standard input: {e}"
            ))
        }
    };

    let username = password_verifier::uid_to_username(target_uid)
        .ok_or_else(|| format!("Could not resolve a Linux account for uid={target_uid}."))?;

    match password_verifier::verify_password(&username, &password) {
        Ok(()) => {
            client.clear_password_fallback_failures(target_uid).await?;
            Ok(AuthenticateResult::Success)
        }
        Err(code) if password_verifier::is_auth_failure(code) => {
            let status = client.record_password_fallback_failure(target_uid).await?;
            if status.retry_after_secs > 0 {
                Ok(AuthenticateResult::Locked(format!(
                    "Linux password verification failed. Retry in {} seconds.",
                    status.retry_after_secs
                )))
            } else {
                Ok(AuthenticateResult::AuthFailed(
                    "Incorrect Linux account password.".to_string(),
                ))
            }
        }
        Err(code) => Err(format!(
            "Linux password verification failed through PAM service '{}': {}",
            password_verifier::PAM_SERVICE,
            code
        )),
    }
}

async fn authenticate_with_biometrics(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
    backends: &[String],
    security_key_enabled: bool,
    pin_enabled: bool,
    attempt_limit: u8,
) -> Result<AuthenticateResult, String> {
    let system_username = password_verifier::uid_to_username(target_uid)
        .ok_or_else(|| format!("Could not resolve a Linux account for uid={target_uid}."))?;
    let mut last_failure_message = None;

    for _ in 0..attempt_limit {
        match biometrics::verify_group_for_login(backends, &system_username).await {
            biometrics::RuntimeBiometricAttemptResult::Success => {
                return Ok(AuthenticateResult::Success);
            }
            biometrics::RuntimeBiometricAttemptResult::Failed(message) => {
                last_failure_message = Some(message);
                continue;
            }
            biometrics::RuntimeBiometricAttemptResult::Unavailable(message) => {
                return handle_post_biometric_failure(
                    client,
                    target_uid,
                    security_key_enabled,
                    pin_enabled,
                    format!("{message}\nMyKey biometric verification could not complete."),
                )
                .await;
            }
        }
    }

    let attempt_summary = format!(
        "MyKey {} verification did not succeed after {} attempt{}.",
        biometric_stage_label(backends),
        attempt_limit,
        if attempt_limit == 1 { "" } else { "s" }
    );
    handle_post_biometric_failure(
        client,
        target_uid,
        security_key_enabled,
        pin_enabled,
        combine_stage_messages(last_failure_message, attempt_summary),
    )
    .await
}

async fn authenticate_with_security_key(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
    pin_enabled: bool,
) -> Result<AuthenticateResult, String> {
    authenticate_with_security_key_stage(client, target_uid, pin_enabled, None).await
}

async fn authenticate_with_security_key_stage(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
    pin_enabled: bool,
    prior_stage_message: Option<String>,
) -> Result<AuthenticateResult, String> {
    match security_keys::verify_for_login(target_uid) {
        security_keys::RuntimeVerificationResult::Success => Ok(AuthenticateResult::Success),
        security_keys::RuntimeVerificationResult::Failed => {
            fallback_to_pin_after_backend_failure(
                client,
                target_uid,
                pin_enabled,
                combine_stage_messages(
                    prior_stage_message,
                    "MyKey security-key verification did not succeed.\nFalling back to your MyKey PIN for this login.".to_string(),
                ),
            )
            .await
        }
        security_keys::RuntimeVerificationResult::Unavailable(message) => {
            fallback_to_pin_after_backend_failure(
                client,
                target_uid,
                pin_enabled,
                combine_stage_messages(
                    prior_stage_message,
                    format!("{message}\nFalling back to your MyKey PIN for this login."),
                ),
            )
            .await
        }
    }
}

async fn handle_post_biometric_failure(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
    security_key_enabled: bool,
    pin_enabled: bool,
    message: String,
) -> Result<AuthenticateResult, String> {
    if security_key_enabled {
        return authenticate_with_security_key_stage(
            client,
            target_uid,
            pin_enabled,
            Some(format!(
                "{message}\nTrying your MyKey security key next."
            )),
        )
        .await;
    }

    fallback_to_pin_after_backend_failure(
        client,
        target_uid,
        pin_enabled,
        format!("{message}\nFalling back to your MyKey PIN for this login."),
    )
    .await
}

async fn fallback_to_pin_after_backend_failure(
    client: &daemon_client::DaemonClient,
    target_uid: u32,
    pin_enabled: bool,
    message: String,
) -> Result<AuthenticateResult, String> {
    if !pin_enabled {
        return Ok(AuthenticateResult::AuthFailed(message));
    }

    let status = client
        .pin_status(target_uid)
        .await
        .map_err(|e| format!("Could not read MyKey PIN fallback status: {e}"))?;

    if !status.is_set {
        return Ok(AuthenticateResult::NotConfigured(
            "MyKey PIN fallback is not configured. Run: mykey-pin set".to_string(),
        ));
    }
    if status.cooldown_remaining_secs > 0 {
        return Ok(AuthenticateResult::Locked(format!(
            "{message}\nMyKey PIN fallback is locked. Try again in {} seconds.",
            status.cooldown_remaining_secs
        )));
    }

    Ok(AuthenticateResult::PinFallbackRequired(message))
}

fn combine_stage_messages(prefix: Option<String>, suffix: String) -> String {
    match prefix {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}\n{suffix}"),
        _ => suffix,
    }
}

fn biometric_stage_label(backends: &[String]) -> &'static str {
    match backends {
        [backend] if backend == "fprintd" => "fingerprint",
        [backend] if backend == "howdy" => "face",
        _ => "biometric",
    }
}

fn read_password_from_stdin() -> Result<Zeroizing<String>, std::io::Error> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    let text = String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "password is not valid UTF-8"))?;
    Ok(Zeroizing::new(text))
}

async fn run_enable() {
    ensure_root("enable");

    let changed = enable_base_pam_targets();

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

    println!(
        "If no MyKey PIN is configured yet, supported PAM prompts will use MyKey-managed Linux password fallback until you run: mykey-pin set"
    );
    maybe_offer_login_setup();
}

async fn run_setup() {
    ensure_root("setup");

    if !is_interactive_terminal() {
        eprintln!("mykey-auth setup requires an interactive terminal.");
        std::process::exit(1);
    }

    let target_uid = preferred_target_uid();
    let system_username = preferred_target_username().unwrap_or_else(|| target_uid.to_string());

    if let Err(e) = ensure_daemon_ready(target_uid).await {
        eprintln!("{e}");
        std::process::exit(1);
    }

    println!("MyKey auth setup for Linux account '{}'.", system_username);
    println!();

    let mut pin_is_set = match read_pin_status(target_uid).await {
        Ok(status) => status.is_set,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    println!("Step 1: PIN");
    if pin_is_set {
        println!("MyKey PIN is already configured for this account.");
    } else {
        match prompt_yes_no(
            "Would you like to set up a PIN? This is the MyKey default method of authorization. [Y/n]: ",
            true,
        ) {
            Ok(true) => {
                if let Err(e) = run_peer_binary("mykey-pin", &["set"]) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                pin_is_set = match read_pin_status(target_uid).await {
                    Ok(status) => status.is_set,
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                };
                if !pin_is_set {
                    eprintln!("MyKey PIN setup did not complete successfully.");
                    std::process::exit(1);
                }
            }
            Ok(false) => {
                println!(
                    "MyKey will use Linux password fallback for supported PAM prompts until a PIN is configured."
                );
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    let mut overview = match read_local_auth_overview(target_uid).await {
        Ok(overview) => overview,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    if pin_is_set {
        println!();
        println!("Step 2: Security key");
        if overview.local_auth.has_stage("security_key") {
            println!("MyKey security-key auth is already configured for this account.");
        } else if security_key_support_available() {
            match prompt_yes_no(
                "Would you like to set up security-key authorization with MyKey? [y/N]: ",
                false,
            ) {
                Ok(true) => {
                    if let Err(e) = run_peer_binary("mykey-security-key", &["enroll"]) {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                }
                Ok(false) => println!("Security-key setup skipped."),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        } else {
            println!(
                "Security-key tooling was not detected. Install pam-u2f support before using security keys with MyKey."
            );
        }

        overview = match read_local_auth_overview(target_uid).await {
            Ok(overview) => overview,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };

        println!();
        println!("Step 3: Biometrics");
        if !overview.local_auth.biometric_backends.is_empty() {
            println!(
                "MyKey biometrics are already configured for: {}",
                overview.local_auth.biometric_backends.join(", ")
            );
        } else {
            let biometric_backends = detected_biometric_backends();
            if biometric_backends.is_empty() {
                println!(
                    "No supported biometric providers were detected. Install fprintd and/or Howdy before using MyKey biometrics."
                );
            } else {
                println!(
                    "Detected biometric providers: {}",
                    biometric_backends.join(", ")
                );
                match prompt_yes_no(
                    "Would you like to set up biometric authorization with MyKey? [y/N]: ",
                    false,
                ) {
                    Ok(true) => {
                        if let Err(e) = run_self_subcommand(&["biometrics"]) {
                            eprintln!("{e}");
                            std::process::exit(1);
                        }
                    }
                    Ok(false) => println!("Biometric setup skipped."),
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                }
            }
        }
    } else {
        println!();
        println!("Skipping security-key and biometric setup because MyKey PIN fallback is not configured.");
    }

    println!();
    println!("Step 4: Base PAM takeover");
    let changed = enable_base_pam_targets();
    if changed.is_empty() {
        println!("MyKey PAM integration is already enabled for supported base targets.");
    } else {
        println!("Enabled MyKey PAM integration for: {}", changed.join(", "));
    }

    println!();
    println!("Step 5: Login and unlock");
    let login_inspections = match pam_integration::inspect_targets(pam_integration::LOGIN_TARGETS) {
        Ok(inspections) => inspections,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let detected_login_targets: Vec<_> = login_inspections
        .iter()
        .copied()
        .filter(|inspection| inspection.is_present())
        .collect();
    if detected_login_targets.is_empty() {
        println!("No supported login or unlock PAM targets were detected on this system.");
    } else {
        let names = detected_login_targets
            .iter()
            .map(|inspection| inspection.target.name)
            .collect::<Vec<_>>()
            .join(", ");
        let prompt = format!(
            "{names} detected. Would you like to use MyKey authorizations for logging into your system? [y/N]: "
        );
        match prompt_yes_no(&prompt, false) {
            Ok(true) => {
                if let Err(e) = run_self_subcommand(&["login"]) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
            Ok(false) => println!("Login and unlock PAM targets were left unchanged."),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    println!();
    match local_auth_summary(target_uid).await {
        Ok(summary) => println!("MyKey auth setup complete. Current local auth: {summary}"),
        Err(e) => println!("MyKey auth setup complete. Current local auth could not be read ({e})."),
    }
    println!("Run `mykey status` to review the current PAM and local-auth state.");
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
    match read_local_auth_overview(target_uid).await {
        Ok(overview) => {
            println!("MyKey local auth: {}", overview.summary);
            println!(
                "  - Normal password fallback: {}",
                policy_label(overview.local_auth.password_fallback_allowed)
            );
            println!(
                "  - Elevated MyKey actions require password: {}",
                yes_no_label(overview.local_auth.elevated_password_required)
            );
            if overview.local_auth.has_stage("biometric") {
                println!(
                    "  - Biometric attempt limit: {}",
                    overview.local_auth.biometric_attempt_limit
                );
            }
        }
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
    Ok(read_local_auth_overview(target_uid).await?.summary)
}

struct LocalAuthOverview {
    summary: String,
    local_auth: daemon_client::LocalAuthStatus,
}

async fn read_local_auth_overview(target_uid: u32) -> Result<LocalAuthOverview, String> {
    let client = daemon_client::DaemonClient::connect().await?;
    let local_auth = client.local_auth_status(target_uid).await?;
    let pin_status = client.pin_status(target_uid).await?;
    client.disconnect().await;

    if !local_auth.enabled || !pin_status.is_set {
        return Ok(LocalAuthOverview {
            summary: if local_auth.password_fallback_allowed {
                "password fallback only".to_string()
            } else {
                "unconfigured".to_string()
            },
            local_auth,
        });
    }

    let summary = if local_auth.has_stage("pin")
        && !local_auth.has_stage("biometric")
        && !local_auth.has_stage("security_key")
    {
        if pin_status.cooldown_remaining_secs > 0 {
            format!(
                "configured (pin, locked {}s)",
                pin_status.cooldown_remaining_secs
            )
        } else {
            "configured (pin)".to_string()
        }
    } else {
        format!("configured ({})", format_auth_chain(&local_auth))
    };

    Ok(LocalAuthOverview {
        summary,
        local_auth,
    })
}

fn policy_label(value: bool) -> &'static str {
    if value {
        "allowed"
    } else {
        "blocked"
    }
}

fn yes_no_label(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_auth_chain(local_auth: &daemon_client::LocalAuthStatus) -> String {
    let mut labels = Vec::new();
    if local_auth.has_stage("biometric") {
        if local_auth.biometric_backends.is_empty() {
            labels.push("biometric".to_string());
        } else if local_auth.biometric_backends.len() == 1 {
            labels.push(local_auth.biometric_backends[0].clone());
        } else {
            labels.push(format!(
                "biometrics [{}]",
                local_auth.biometric_backends.join(", ")
            ));
        }
    }
    if local_auth.has_stage("security_key") {
        labels.push("security key".to_string());
    }
    if local_auth.has_stage("pin") {
        labels.push("pin".to_string());
    }

    if labels.is_empty() {
        "unknown".to_string()
    } else {
        labels.join(" -> ")
    }
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

fn enable_base_pam_targets() -> Vec<String> {
    match pam_integration::enable_targets(pam_integration::BASE_TARGETS) {
        Ok(changed) => changed,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

async fn ensure_daemon_ready(target_uid: u32) -> Result<(), String> {
    read_local_auth_overview(target_uid)
        .await
        .map(|_| ())
        .map_err(|e| {
            format!(
                "mykey-daemon is not ready for setup: {e}\nVerify it is running with: sudo systemctl status mykey-daemon"
            )
        })
}

async fn read_pin_status(target_uid: u32) -> Result<daemon_client::PinStatus, String> {
    let client = daemon_client::DaemonClient::connect().await?;
    let pin_status = client.pin_status(target_uid).await?;
    client.disconnect().await;
    Ok(pin_status)
}

fn run_peer_binary(binary_name: &str, args: &[&str]) -> Result<(), String> {
    let binary = resolve_binary_path(binary_name);
    let status = std::process::Command::new(&binary)
        .args(args)
        .status()
        .map_err(|e| format!("Could not launch {}: {e}", binary.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} exited with status {}",
            binary.display(),
            status.code().unwrap_or_default()
        ))
    }
}

fn run_self_subcommand(args: &[&str]) -> Result<(), String> {
    let current = std::env::current_exe()
        .map_err(|e| format!("Could not resolve the current mykey-auth binary: {e}"))?;
    let status = std::process::Command::new(&current)
        .args(args)
        .status()
        .map_err(|e| format!("Could not relaunch {}: {e}", current.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {} exited with status {}",
            current.display(),
            args.join(" "),
            status.code().unwrap_or_default()
        ))
    }
}

fn resolve_binary_path(binary_name: &str) -> std::path::PathBuf {
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            let sibling = parent.join(binary_name);
            if sibling.exists() {
                return sibling;
            }
        }
    }
    for candidate in [
        std::path::PathBuf::from("/usr/bin").join(binary_name),
        std::path::PathBuf::from("/usr/local/bin").join(binary_name),
    ] {
        if candidate.exists() {
            return candidate;
        }
    }
    std::path::PathBuf::from(binary_name)
}

fn detected_biometric_backends() -> Vec<&'static str> {
    let mut detected = Vec::new();
    if command_exists("fprintd-enroll") && command_exists("fprintd-verify") {
        detected.push("fprintd");
    }
    if command_exists("howdy") {
        detected.push("howdy");
    }
    detected
}

fn security_key_support_available() -> bool {
    PAM_U2F_CFG_CANDIDATES
        .iter()
        .any(|candidate| std::path::Path::new(candidate).exists())
        && PAM_U2F_MODULE_CANDIDATES
            .iter()
            .any(|candidate| std::path::Path::new(candidate).exists())
        && SECURITY_KEY_PAM_SERVICE_CANDIDATES
            .iter()
            .any(|candidate| std::path::Path::new(candidate).exists())
}

fn command_exists(name: &str) -> bool {
    let resolved = resolve_binary_path(name);
    if resolved.exists() {
        return true;
    }

    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(name))
                .any(|candidate| candidate.exists())
        })
        .unwrap_or(false)
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
    use super::{parse_args, preflight_mode_label, AuthMode, AuthenticateInput, Command};

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
            Command::Authenticate { target_uid, input } => {
                assert_eq!(target_uid, 1000);
                assert_eq!(input, AuthenticateInput::PinFromStdin);
            }
            _ => panic!("expected authenticate command"),
        }
    }

    #[test]
    fn parse_authenticate_args_accepts_biometric_first_call_without_pin() {
        let args = vec![
            "mykey-auth".to_string(),
            "authenticate".to_string(),
            "--uid".to_string(),
            "1000".to_string(),
        ];

        let parsed = parse_args(&args).expect("arguments should parse");
        match parsed {
            Command::Authenticate { target_uid, input } => {
                assert_eq!(target_uid, 1000);
                assert_eq!(input, AuthenticateInput::None);
            }
            _ => panic!("expected authenticate command"),
        }
    }

    #[test]
    fn parse_authenticate_args_accepts_password_stdin() {
        let args = vec![
            "mykey-auth".to_string(),
            "authenticate".to_string(),
            "--uid".to_string(),
            "1000".to_string(),
            "--password-stdin".to_string(),
        ];

        let parsed = parse_args(&args).expect("arguments should parse");
        match parsed {
            Command::Authenticate { target_uid, input } => {
                assert_eq!(target_uid, 1000);
                assert_eq!(input, AuthenticateInput::PasswordFromStdin);
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
    fn parse_setup_command() {
        let args = vec!["mykey-auth".to_string(), "setup".to_string()];
        assert!(matches!(parse_args(&args), Ok(Command::Setup)));
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

    #[test]
    fn preflight_mode_label_describes_runtime_mode() {
        assert_eq!(preflight_mode_label(&AuthMode::PinOnly), "pin");
        assert_eq!(
            preflight_mode_label(&AuthMode::PasswordFallback),
            "password"
        );
        assert_eq!(
            preflight_mode_label(&AuthMode::BiometricFirst {
                backends: vec!["fprintd".to_string()],
                security_key_enabled: false,
                pin_enabled: true,
                attempt_limit: 3,
            }),
            "biometric:fprintd"
        );
        assert_eq!(
            preflight_mode_label(&AuthMode::BiometricFirst {
                backends: vec!["fprintd".to_string(), "howdy".to_string()],
                security_key_enabled: false,
                pin_enabled: true,
                attempt_limit: 3,
            }),
            "biometric-group:fprintd,howdy"
        );
    }
}
