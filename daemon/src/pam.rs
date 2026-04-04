// pam.rs — Async PAM user-presence verification for the daemon.
//
// PAM's conversation function is synchronous and blocks on terminal I/O.
// Calling it directly on an async task would stall the tokio runtime.
// verify_user_presence() offloads the entire PAM interaction to
// tokio::task::spawn_blocking so the async runtime stays responsive.
//
// The conversation handler reads prompts and secret input from /dev/tty,
// bypassing the daemon's stdin (which may not exist) and stdout.
//
// PAM service file: /etc/pam.d/webauthn-proxy  (created by scripts/install.sh)

use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::unix::io::AsRawFd;

use log::{error, info, warn};

// ---------------------------------------------------------------------------
// Public async interface
// ---------------------------------------------------------------------------

/// Verify user presence via PAM in a blocking thread.
///
/// Returns Ok(true) on success, Ok(false) on failure/cancellation, and
/// Err if the blocking task itself fails to spawn or join.
pub async fn verify_user_presence() -> Result<bool, String> {
    tokio::task::spawn_blocking(verify_user_presence_blocking)
        .await
        .map_err(|e| format!("PAM spawn_blocking join error: {e}"))
}

// ---------------------------------------------------------------------------
// Synchronous implementation (runs in a thread pool worker)
// ---------------------------------------------------------------------------

fn verify_user_presence_blocking() -> bool {
    let username = current_username();
    info!("Starting PAM user-presence check for '{}'", username);

    let conv = TtyConversation { username: username.clone() };

    let mut client = match pam::Client::with_conversation("webauthn-proxy", conv) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to initialise PAM client: {}", e);
            return false;
        }
    };

    match client.authenticate() {
        Ok(()) => {
            info!("PAM authentication succeeded for '{}'", username);
            true
        }
        Err(e) => {
            warn!("PAM authentication failed for '{}': {}", username, e);
            false
        }
    }
}

// ---------------------------------------------------------------------------
// PAM conversation handler
// ---------------------------------------------------------------------------

struct TtyConversation {
    username: String,
}

impl pam::Conversation for TtyConversation {
    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()> {
        let prompt = msg.to_string_lossy().into_owned();
        tty_print(&prompt);
        CString::new(self.username.as_bytes()).map_err(|_| ())
    }

    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()> {
        let prompt = msg.to_string_lossy().into_owned();
        read_tty_secret(&prompt).map_err(|e| {
            error!("Failed to read secret from /dev/tty: {}", e);
        })
    }

    fn info(&mut self, msg: &CStr) {
        let s = msg.to_string_lossy().into_owned();
        info!("PAM info: {}", s);
        tty_print(&format!("{}\n", s));
    }

    fn error(&mut self, msg: &CStr) {
        let s = msg.to_string_lossy().into_owned();
        warn!("PAM error: {}", s);
        tty_print(&format!("Error: {}\n", s));
    }
}

// ---------------------------------------------------------------------------
// /dev/tty helpers
// ---------------------------------------------------------------------------

fn tty_print(msg: &str) {
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = tty.write_all(msg.as_bytes());
        let _ = tty.flush();
    }
}

fn read_tty_secret(prompt: &str) -> Result<CString, String> {
    use std::io::BufRead;

    let mut tty_out = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("Cannot open /dev/tty for writing: {e}"))?;

    let tty_in = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(|e| format!("Cannot open /dev/tty for reading: {e}"))?;

    let fd = tty_in.as_raw_fd();

    write!(tty_out, "{}", prompt).ok();
    tty_out.flush().ok();

    let mut old_term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut old_term) } != 0 {
        return Err(format!("tcgetattr: {}", std::io::Error::last_os_error()));
    }

    let mut no_echo = old_term;
    no_echo.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &no_echo) } != 0 {
        return Err(format!("tcsetattr: {}", std::io::Error::last_os_error()));
    }

    let secret = {
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(&tty_in);
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read_line: {e}"))?;
        line
    };

    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &old_term) };
    writeln!(tty_out).ok();

    let trimmed = secret.trim_end_matches(|c: char| c == '\n' || c == '\r');
    CString::new(trimmed).map_err(|_| "Secret contains a null byte".to_string())
}

// ---------------------------------------------------------------------------
// Username resolution
// ---------------------------------------------------------------------------

fn current_username() -> String {
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() { return u; }
    }
    if let Ok(u) = std::env::var("LOGNAME") {
        if !u.is_empty() { return u; }
    }
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let name = CStr::from_ptr((*pw).pw_name);
            return name.to_string_lossy().into_owned();
        }
    }
    "unknown".to_string()
}
