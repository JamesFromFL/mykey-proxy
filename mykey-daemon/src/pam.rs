// pam.rs — User presence verification via polkit.
//
// The daemon runs as a system user with no terminal. Polkit handles
// authentication dialogs on the user's desktop session correctly.
//
// polkit action: com.mykey.authenticate
// This prompts the user with their system password or fingerprint
// via the desktop's authentication agent.
//
// Retry policy:
//   - Up to 3 pkcheck attempts are allowed inside one verification call.
//   - No daemon-managed cross-session cooldown is applied here.
//   - MyKey PIN brute-force protection is handled separately in the PIN path.

use log::{error, info, warn};
use std::process::Command;

/// Verify user presence using polkit.
///
/// Allows up to 3 pkcheck attempts per call. If all 3 fail, the call returns
/// `Ok(false)` without imposing any daemon-managed cooldown.
pub async fn verify_user_presence(calling_pid: u32) -> Result<bool, String> {
    // ── Up to 3 attempts inside a blocking task ───────────────────────────
    tokio::task::spawn_blocking(move || {
        info!(
            "Starting polkit user-presence check for pid={}",
            calling_pid
        );

        for attempt in 1u32..=3 {
            let output = Command::new("pkcheck")
                .args([
                    "--action-id",
                    "com.mykey.authenticate",
                    "--process",
                    &calling_pid.to_string(),
                    "--allow-user-interaction",
                ])
                .output()
                .map_err(|e| format!("pkcheck failed to run: {e}"))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // pkcheck exit code 0 = authorized.
            // Some polkit versions also print "auth_self" or "auth_admin" to
            // stdout when the action was granted after a credential challenge —
            // accept those as success even if the exit code is non-zero.
            if output.status.success()
                || stdout.contains("auth_self")
                || stdout.contains("auth_admin")
            {
                info!(
                    "Polkit user-presence check succeeded for pid={}",
                    calling_pid
                );
                return Ok(true);
            }

            error!(
                "Polkit attempt {}/3 failed for pid={}: stdout={} stderr={}",
                attempt, calling_pid, stdout, stderr
            );
        }

        warn!(
            "All 3 polkit attempts failed for pid={} — \
             no daemon-managed cooldown is applied to the strong-auth path",
            calling_pid
        );
        Ok(false)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}
