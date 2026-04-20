// lib.rs — PAM module entry point for MyKey PIN authentication.
//
// Exported symbols: pam_sm_authenticate, pam_sm_setcred
// Built as a cdylib; install as /lib/security/mykeypin.so (or libmykeypin.so
// depending on distribution conventions).

use pam::{export_pam_module, PamModule, PamReturnCode};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::raw::c_uint;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

const PIN_HELPER_CANDIDATES: &[&str] = &[
    "/usr/local/bin/mykey-pin-auth",
    "/usr/bin/mykey-pin-auth",
];

// ---------------------------------------------------------------------------
// Inline PAM FFI — avoids assumptions about pam_sys binding details.
// libpam is already linked by the `pam` crate dependency.
// ---------------------------------------------------------------------------

mod pam_ffi {
    use libc::{c_char, c_int, c_void};

    /// PAM message styles (pam_message.msg_style).
    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_ERROR_MSG: c_int = 3;

    /// PAM item type for the conversation struct.
    pub const PAM_CONV_ITEM: c_int = 5;

    #[repr(C)]
    pub struct PamMessage {
        pub msg_style: c_int,
        pub msg: *const c_char,
    }

    #[repr(C)]
    pub struct PamResponse {
        pub resp: *mut c_char,
        pub resp_retcode: c_int,
    }

    #[repr(C)]
    pub struct PamConv {
        pub conv: Option<
            unsafe extern "C" fn(
                num_msg: c_int,
                msg: *mut *const PamMessage,
                resp: *mut *mut PamResponse,
                appdata_ptr: *mut c_void,
            ) -> c_int,
        >,
        pub appdata_ptr: *mut c_void,
    }

    extern "C" {
        /// Retrieve a PAM item from the handle.
        pub fn pam_get_item(
            pamh: *const c_void,
            item_type: c_int,
            item: *mut *const c_void,
        ) -> c_int;

        /// Retrieve the target PAM username from the handle.
        pub fn pam_get_user(
            pamh: *const c_void,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
    }
}

// ---------------------------------------------------------------------------
// Conversation helper
// ---------------------------------------------------------------------------

/// Send a single PAM message and optionally collect the user's response.
///
/// Returns `Some(response)` for echo-off prompts, `None` for error/info messages.
/// Returns `None` on any conversation error.
///
/// # Safety
/// Caller must ensure `handle` points to a valid PAM handle for the duration of
/// this call.
unsafe fn pam_converse(
    handle: &pam::PamHandle,
    msg_style: libc::c_int,
    msg: &str,
) -> Option<String> {
    use pam_ffi::*;

    let mut conv_ptr: *const libc::c_void = std::ptr::null();
    let rc = pam_get_item(
        handle as *const pam::PamHandle as *const libc::c_void,
        PAM_CONV_ITEM,
        &mut conv_ptr,
    );
    if rc != 0 || conv_ptr.is_null() {
        return None;
    }
    let conv = &*(conv_ptr as *const PamConv);
    let conv_fn = conv.conv?;

    let c_msg = CString::new(msg).ok()?;
    let pam_msg = PamMessage {
        msg_style,
        msg: c_msg.as_ptr(),
    };
    let pam_msg_ptr: *const PamMessage = &pam_msg;
    let mut msg_array: [*const PamMessage; 1] = [pam_msg_ptr];
    let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

    let rc = conv_fn(
        1,
        msg_array.as_mut_ptr() as *mut *const PamMessage,
        &mut resp_ptr,
        conv.appdata_ptr,
    );

    if rc != 0 {
        if !resp_ptr.is_null() {
            libc::free(resp_ptr as *mut libc::c_void);
        }
        return None;
    }

    if msg_style == PAM_PROMPT_ECHO_OFF {
        if resp_ptr.is_null() {
            return None;
        }
        let resp = &*resp_ptr;
        let result = if !resp.resp.is_null() {
            let s = CStr::from_ptr(resp.resp).to_string_lossy().into_owned();
            libc::free(resp.resp as *mut libc::c_void);
            Some(s)
        } else {
            None
        };
        libc::free(resp_ptr as *mut libc::c_void);
        result
    } else {
        if !resp_ptr.is_null() {
            libc::free(resp_ptr as *mut libc::c_void);
        }
        None
    }
}

unsafe fn pam_user(handle: &pam::PamHandle) -> Option<String> {
    let mut user_ptr: *const libc::c_char = std::ptr::null();
    let rc = pam_ffi::pam_get_user(
        handle as *const pam::PamHandle as *const libc::c_void,
        &mut user_ptr,
        std::ptr::null(),
    );
    if rc != 0 || user_ptr.is_null() {
        return None;
    }
    Some(CStr::from_ptr(user_ptr).to_string_lossy().into_owned())
}

fn user_to_uid(username: &str) -> Option<u32> {
    let username = CString::new(username).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let rc = unsafe {
            libc::getpwnam_r(
                username.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return None;
            }
            let pwd = unsafe { pwd.assume_init() };
            return Some(pwd.pw_uid);
        }
        if rc == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return None;
    }
}

enum HelperVerifyResult {
    Success,
    AuthFailed,
    Locked(String),
    NotConfigured(String),
    Error(String),
}

fn run_pin_helper_verify(uid: u32, pin: &[u8]) -> HelperVerifyResult {
    let helper_path = match resolve_pin_helper_path() {
        Some(path) => path,
        None => {
            return HelperVerifyResult::Error(
                "Could not find an installed mykey-pin-auth helper.".to_string(),
            );
        }
    };

    let mut child = match Command::new(helper_path)
        .args(["verify", "--uid", &uid.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return HelperVerifyResult::Error(format!(
                "Could not launch mykey-pin-auth: {e}"
            ));
        }
    };

    if let Some(stdin) = child.stdin.as_mut() {
        if let Err(e) = stdin.write_all(pin) {
            let _ = child.kill();
            let _ = child.wait();
            return HelperVerifyResult::Error(format!(
                "Could not send PIN to mykey-pin-auth: {e}"
            ));
        }
    } else {
        let _ = child.kill();
        let _ = child.wait();
        return HelperVerifyResult::Error(
            "mykey-pin-auth did not expose a writable stdin".to_string(),
        );
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            return HelperVerifyResult::Error(format!(
                "Failed waiting for mykey-pin-auth: {e}"
            ));
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match output.status.code() {
        Some(0) => HelperVerifyResult::Success,
        Some(1) => HelperVerifyResult::AuthFailed,
        Some(3) => HelperVerifyResult::Locked(stderr),
        Some(4) => HelperVerifyResult::NotConfigured(stderr),
        Some(2) => HelperVerifyResult::Error(stderr),
        Some(code) => HelperVerifyResult::Error(format!(
            "mykey-pin-auth exited unexpectedly with status {code}"
        )),
        None => HelperVerifyResult::Error(
            "mykey-pin-auth terminated without an exit status".to_string(),
        ),
    }
}

fn resolve_pin_helper_path() -> Option<&'static str> {
    PIN_HELPER_CANDIDATES
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).is_file())
}

unsafe fn pam_error(handle: &pam::PamHandle, msg: &str) {
    let _ = pam_converse(handle, pam_ffi::PAM_ERROR_MSG, msg);
}

// ---------------------------------------------------------------------------
// PAM module implementation
// ---------------------------------------------------------------------------

/// MyKey PIN PAM module.
pub struct MyKeyPinModule;

impl PamModule for MyKeyPinModule {
    /// Authenticate the user by prompting for a PIN and dispatching helper verification.
    fn authenticate(
        handle: &pam::PamHandle,
        _args: Vec<&CStr>,
        _flags: c_uint,
    ) -> PamReturnCode {
        let username = unsafe {
            match pam_user(handle) {
                Some(user) => user,
                None => {
                    pam_error(handle, "Could not resolve the PAM target user.");
                    return PamReturnCode::Auth_Err;
                }
            }
        };

        let uid = match user_to_uid(&username) {
            Some(uid) => uid,
            None => {
                unsafe {
                    pam_error(
                        handle,
                        "Could not resolve the target account for MyKey PIN authentication.",
                    );
                }
                return PamReturnCode::Auth_Err;
            }
        };

        let entered_pin = unsafe {
            match pam_converse(handle, pam_ffi::PAM_PROMPT_ECHO_OFF, "MyKey PIN: ") {
                Some(pin) => Zeroizing::new(pin),
                None => return PamReturnCode::Auth_Err,
            }
        };

        match run_pin_helper_verify(uid, entered_pin.as_bytes()) {
            HelperVerifyResult::Success => PamReturnCode::Success,
            HelperVerifyResult::AuthFailed => {
                unsafe {
                    pam_error(handle, "Incorrect MyKey PIN.");
                }
                PamReturnCode::Auth_Err
            }
            HelperVerifyResult::Locked(msg)
            | HelperVerifyResult::NotConfigured(msg)
            | HelperVerifyResult::Error(msg) => {
                unsafe {
                    pam_error(handle, if msg.is_empty() {
                        "MyKey PIN authentication failed."
                    } else {
                        &msg
                    });
                }
                PamReturnCode::Auth_Err
            }
        }
    }

    /// No-op; credential management is not required for this module.
    fn set_credentials(
        _handle: &pam::PamHandle,
        _args: Vec<&CStr>,
        _flags: c_uint,
    ) -> PamReturnCode {
        PamReturnCode::Success
    }
}

export_pam_module!(MyKeyPinModule);
