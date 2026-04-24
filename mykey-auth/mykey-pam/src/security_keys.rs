use std::path::Path;
use std::process::{Command, Stdio};

const SECURITY_KEY_AUTH_HELPER_CANDIDATES: &[&str] = &[
    "/usr/local/bin/mykey-security-key-auth",
    "/usr/bin/mykey-security-key-auth",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeVerificationResult {
    Success,
    Failed,
    Unavailable(String),
}

pub fn verify_for_login(target_uid: u32) -> RuntimeVerificationResult {
    let helper_path = match resolve_helper_path() {
        Some(path) => path,
        None => {
            return RuntimeVerificationResult::Unavailable(
                "Could not find the installed mykey-security-key-auth helper.".to_string(),
            );
        }
    };

    let uid_arg = target_uid.to_string();
    let status = Command::new(helper_path)
        .args(["verify", "--uid", uid_arg.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();

    match status {
        Ok(status) if status.success() => RuntimeVerificationResult::Success,
        Ok(status) if status.code() == Some(1) => RuntimeVerificationResult::Failed,
        Ok(status) if status.code() == Some(2) => RuntimeVerificationResult::Unavailable(
            "MyKey security-key verification could not complete through the dedicated PAM service."
                .to_string(),
        ),
        Ok(status) => RuntimeVerificationResult::Unavailable(format!(
            "mykey-security-key-auth exited unexpectedly with status {}",
            status
                .code()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        )),
        Err(e) => RuntimeVerificationResult::Unavailable(format!(
            "Could not launch mykey-security-key-auth: {e}"
        )),
    }
}

fn resolve_helper_path() -> Option<&'static str> {
    SECURITY_KEY_AUTH_HELPER_CANDIDATES
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
}
