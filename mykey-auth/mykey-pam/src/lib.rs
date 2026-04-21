// lib.rs — PAM module entry point for unified MyKey local authentication.
//
// Phase A:
//   - this is the new top-level PAM entrypoint for MyKey
//   - it still authenticates through the existing MyKey PIN backend
//   - future phases will add biometric-first auth before PIN fallback

use pam::{export_pam_module, PamModule, PamReturnCode};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::raw::c_uint;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

const AUTH_HELPER_CANDIDATES: &[&str] = &[
    "/usr/local/bin/mykey-auth",
    "/usr/bin/mykey-auth",
];

mod pam_ffi {
    use libc::{c_char, c_int, c_void};

    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_ERROR_MSG: c_int = 3;
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
        pub fn pam_get_item(
            pamh: *const c_void,
            item_type: c_int,
            item: *mut *const c_void,
        ) -> c_int;

        pub fn pam_get_user(
            pamh: *const c_void,
            user: *mut *const c_char,
            prompt: *const c_char,
        ) -> c_int;
    }
}

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

enum HelperAuthResult {
    Success,
    AuthFailed,
    Locked(String),
    NotConfigured(String),
    Error(String),
}

fn run_auth_helper(uid: u32, pin: &[u8]) -> HelperAuthResult {
    let helper_path = match resolve_auth_helper_path() {
        Some(path) => path,
        None => {
            return HelperAuthResult::Error(
                "Could not find an installed mykey-auth helper.".to_string(),
            );
        }
    };

    let mut child = match Command::new(helper_path)
        .args(["authenticate", "--uid", &uid.to_string(), "--pin-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return HelperAuthResult::Error(format!("Could not launch mykey-auth: {e}"));
        }
    };

    if let Some(stdin) = child.stdin.as_mut() {
        if let Err(e) = stdin.write_all(pin) {
            let _ = child.kill();
            let _ = child.wait();
            return HelperAuthResult::Error(format!(
                "Could not send PIN to mykey-auth: {e}"
            ));
        }
    } else {
        let _ = child.kill();
        let _ = child.wait();
        return HelperAuthResult::Error(
            "mykey-auth did not expose a writable stdin".to_string(),
        );
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            return HelperAuthResult::Error(format!(
                "Failed waiting for mykey-auth: {e}"
            ));
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match output.status.code() {
        Some(0) => HelperAuthResult::Success,
        Some(1) => HelperAuthResult::AuthFailed,
        Some(3) => HelperAuthResult::Locked(stderr),
        Some(4) => HelperAuthResult::NotConfigured(stderr),
        Some(2) => HelperAuthResult::Error(stderr),
        Some(code) => HelperAuthResult::Error(format!(
            "mykey-auth exited unexpectedly with status {code}"
        )),
        None => HelperAuthResult::Error(
            "mykey-auth terminated without an exit status".to_string(),
        ),
    }
}

fn resolve_auth_helper_path() -> Option<&'static str> {
    AUTH_HELPER_CANDIDATES
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).is_file())
}

unsafe fn pam_error(handle: &pam::PamHandle, msg: &str) {
    let _ = pam_converse(handle, pam_ffi::PAM_ERROR_MSG, msg);
}

pub struct MyKeyModule;

impl PamModule for MyKeyModule {
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
                        "Could not resolve the target account for MyKey authentication.",
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

        match run_auth_helper(uid, entered_pin.as_bytes()) {
            HelperAuthResult::Success => PamReturnCode::Success,
            HelperAuthResult::AuthFailed => {
                unsafe {
                    pam_error(handle, "Incorrect MyKey PIN.");
                }
                PamReturnCode::Auth_Err
            }
            HelperAuthResult::Locked(msg)
            | HelperAuthResult::NotConfigured(msg)
            | HelperAuthResult::Error(msg) => {
                unsafe {
                    pam_error(
                        handle,
                        if msg.is_empty() {
                            "MyKey authentication failed."
                        } else {
                            &msg
                        },
                    );
                }
                PamReturnCode::Auth_Err
            }
        }
    }

    fn set_credentials(
        _handle: &pam::PamHandle,
        _args: Vec<&CStr>,
        _flags: c_uint,
    ) -> PamReturnCode {
        PamReturnCode::Success
    }
}

export_pam_module!(MyKeyModule);
