// lib.rs — PAM module entry point for unified MyKey local authentication.
//
// Runtime behavior:
//   - this is the top-level PAM entrypoint for MyKey local auth
//   - it asks the helper which runtime mode is active
//   - it performs biometric-first auth when configured, then prompts for PIN fallback
//   - it prompts for Linux password directly when MyKey-managed password fallback is active

use pam::{export_pam_module, PamModule, PamReturnCode};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::raw::c_uint;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

const AUTH_HELPER_CANDIDATES: &[&str] = &["/usr/local/bin/mykey-auth", "/usr/bin/mykey-auth"];

mod pam_ffi {
    use libc::{c_char, c_int, c_void};

    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_ERROR_MSG: c_int = 3;
    pub const PAM_TEXT_INFO: c_int = 4;
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

        pub fn pam_get_data(
            pamh: *const c_void,
            module_data_name: *const c_char,
            data: *mut *const c_void,
        ) -> c_int;

        pub fn pam_set_data(
            pamh: *mut c_void,
            module_data_name: *const c_char,
            data: *mut c_void,
            cleanup: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int)>,
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

unsafe fn pam_message(handle: &pam::PamHandle, msg_style: libc::c_int, msg: &str) {
    let _ = pam_converse(handle, msg_style, msg);
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
    PinFallbackRequired(String),
    Locked(String),
    NotConfigured,
    Error(String),
}

enum HelperPreflightResult {
    Ready(HelperAuthMode),
    Ignore,
    Locked(String),
    Error(String),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthResumeState {
    None = 0,
    PinFallback = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthLockMessageState {
    NotShown = 0,
    Shown = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HelperAuthMode {
    PinOnly,
    PasswordFallback,
    BiometricFirst { backends: Vec<String> },
    SecurityKeyFirst,
}

enum HelperAuthInput<'a> {
    None,
    Pin(&'a [u8]),
    Password(&'a [u8]),
}

const AUTH_RESUME_STATE_KEY: &[u8] = b"mykey.auth.resume_state\0";
const AUTH_LOCK_MESSAGE_STATE_KEY: &[u8] = b"mykey.auth.lock_message_state\0";

unsafe extern "C" fn pam_auth_resume_state_cleanup(
    _pamh: *mut libc::c_void,
    data: *mut libc::c_void,
    _error_status: libc::c_int,
) {
    if !data.is_null() {
        drop(Box::from_raw(data as *mut AuthResumeState));
    }
}

unsafe extern "C" fn pam_auth_lock_message_state_cleanup(
    _pamh: *mut libc::c_void,
    data: *mut libc::c_void,
    _error_status: libc::c_int,
) {
    if !data.is_null() {
        drop(Box::from_raw(data as *mut AuthLockMessageState));
    }
}

unsafe fn pam_handle_ptr(handle: &pam::PamHandle) -> *mut libc::c_void {
    handle as *const pam::PamHandle as *mut libc::c_void
}

unsafe fn pam_get_auth_resume_state(handle: &pam::PamHandle) -> AuthResumeState {
    let mut data_ptr: *const libc::c_void = std::ptr::null();
    let rc = pam_ffi::pam_get_data(
        pam_handle_ptr(handle),
        AUTH_RESUME_STATE_KEY.as_ptr() as *const libc::c_char,
        &mut data_ptr,
    );
    if rc != 0 || data_ptr.is_null() {
        return AuthResumeState::None;
    }

    match *(data_ptr as *const AuthResumeState) {
        AuthResumeState::PinFallback => AuthResumeState::PinFallback,
        AuthResumeState::None => AuthResumeState::None,
    }
}

unsafe fn pam_set_auth_resume_state(
    handle: &pam::PamHandle,
    state: AuthResumeState,
) -> Result<(), ()> {
    let mut data_ptr: *const libc::c_void = std::ptr::null();
    let handle_ptr = pam_handle_ptr(handle);
    let key_ptr = AUTH_RESUME_STATE_KEY.as_ptr() as *const libc::c_char;

    if pam_ffi::pam_get_data(handle_ptr, key_ptr, &mut data_ptr) == 0 && !data_ptr.is_null() {
        *(data_ptr as *mut AuthResumeState) = state;
        return Ok(());
    }

    let raw = Box::into_raw(Box::new(state));
    let rc = pam_ffi::pam_set_data(
        handle_ptr,
        key_ptr,
        raw as *mut libc::c_void,
        Some(pam_auth_resume_state_cleanup),
    );
    if rc == 0 {
        Ok(())
    } else {
        drop(Box::from_raw(raw));
        Err(())
    }
}

unsafe fn pam_get_auth_lock_message_state(handle: &pam::PamHandle) -> AuthLockMessageState {
    let mut data_ptr: *const libc::c_void = std::ptr::null();
    let rc = pam_ffi::pam_get_data(
        pam_handle_ptr(handle),
        AUTH_LOCK_MESSAGE_STATE_KEY.as_ptr() as *const libc::c_char,
        &mut data_ptr,
    );
    if rc != 0 || data_ptr.is_null() {
        return AuthLockMessageState::NotShown;
    }

    match *(data_ptr as *const AuthLockMessageState) {
        AuthLockMessageState::Shown => AuthLockMessageState::Shown,
        AuthLockMessageState::NotShown => AuthLockMessageState::NotShown,
    }
}

unsafe fn pam_set_auth_lock_message_state(
    handle: &pam::PamHandle,
    state: AuthLockMessageState,
) -> Result<(), ()> {
    let mut data_ptr: *const libc::c_void = std::ptr::null();
    let handle_ptr = pam_handle_ptr(handle);
    let key_ptr = AUTH_LOCK_MESSAGE_STATE_KEY.as_ptr() as *const libc::c_char;

    if pam_ffi::pam_get_data(handle_ptr, key_ptr, &mut data_ptr) == 0 && !data_ptr.is_null() {
        *(data_ptr as *mut AuthLockMessageState) = state;
        return Ok(());
    }

    let raw = Box::into_raw(Box::new(state));
    let rc = pam_ffi::pam_set_data(
        handle_ptr,
        key_ptr,
        raw as *mut libc::c_void,
        Some(pam_auth_lock_message_state_cleanup),
    );
    if rc == 0 {
        Ok(())
    } else {
        drop(Box::from_raw(raw));
        Err(())
    }
}

fn run_auth_helper(uid: u32, input: HelperAuthInput<'_>) -> HelperAuthResult {
    let uid_arg = uid.to_string();
    let mut args = vec!["authenticate", "--uid", uid_arg.as_str()];
    let stdin_data = match input {
        HelperAuthInput::None => None,
        HelperAuthInput::Pin(pin) => {
            args.push("--pin-stdin");
            Some(pin)
        }
        HelperAuthInput::Password(password) => {
            args.push("--password-stdin");
            Some(password)
        }
    };

    match run_helper_command(&args, stdin_data) {
        Ok((Some(0), _, _)) => HelperAuthResult::Success,
        Ok((Some(1), _, _)) => HelperAuthResult::AuthFailed,
        Ok((Some(3), _, stderr)) => HelperAuthResult::Locked(stderr),
        Ok((Some(4), _, stderr)) => {
            if stderr.is_empty() {
                HelperAuthResult::NotConfigured
            } else {
                HelperAuthResult::Error(stderr)
            }
        }
        Ok((Some(5), _, stderr)) => HelperAuthResult::PinFallbackRequired(stderr),
        Ok((Some(2), _, stderr)) => HelperAuthResult::Error(stderr),
        Ok((Some(code), _, _)) => {
            HelperAuthResult::Error(format!("mykey-auth exited unexpectedly with status {code}"))
        }
        Ok((None, _, _)) => {
            HelperAuthResult::Error("mykey-auth terminated without an exit status".to_string())
        }
        Err(e) => HelperAuthResult::Error(e),
    }
}

fn run_preflight_helper(uid: u32, force_pin_fallback: bool) -> HelperPreflightResult {
    let uid_arg = uid.to_string();
    let mut args = vec!["preflight", "--uid", uid_arg.as_str()];
    if force_pin_fallback {
        args.push("--pin-fallback");
    }

    match run_helper_command(&args, None) {
        Ok((Some(0), stdout, _)) => match parse_preflight_mode(&stdout) {
            Ok(mode) => HelperPreflightResult::Ready(mode),
            Err(e) => HelperPreflightResult::Error(e),
        },
        Ok((Some(4), _, _)) => HelperPreflightResult::Ignore,
        Ok((Some(3), _, stderr)) => HelperPreflightResult::Locked(stderr),
        Ok((Some(2), _, stderr)) => HelperPreflightResult::Error(stderr),
        Ok((Some(code), _, _)) => HelperPreflightResult::Error(format!(
            "mykey-auth exited unexpectedly with status {code}"
        )),
        Ok((None, _, _)) => {
            HelperPreflightResult::Error("mykey-auth terminated without an exit status".to_string())
        }
        Err(e) => HelperPreflightResult::Error(e),
    }
}

fn run_helper_command(
    args: &[&str],
    stdin_data: Option<&[u8]>,
) -> Result<(Option<i32>, String, String), String> {
    let helper_path = match resolve_auth_helper_path() {
        Some(path) => path,
        None => {
            return Err("Could not find an installed mykey-auth helper.".to_string());
        }
    };

    let mut child = match Command::new(helper_path)
        .args(args)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return Err(format!("Could not launch mykey-auth: {e}")),
    };

    if let Some(pin) = stdin_data {
        if let Some(stdin) = child.stdin.as_mut() {
            if let Err(e) = stdin.write_all(pin) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("Could not send PIN to mykey-auth: {e}"));
            }
        } else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("mykey-auth did not expose a writable stdin".to_string());
        }
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => return Err(format!("Failed waiting for mykey-auth: {e}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok((output.status.code(), stdout, stderr))
}

fn parse_preflight_mode(stdout: &str) -> Result<HelperAuthMode, String> {
    let stdout = stdout.trim();
    if stdout == "pin" {
        return Ok(HelperAuthMode::PinOnly);
    }
    if stdout == "password" {
        return Ok(HelperAuthMode::PasswordFallback);
    }

    if stdout.is_empty() {
        return Err("mykey-auth preflight returned no runtime mode.".to_string());
    }

    if let Some(backend) = stdout.strip_prefix("biometric:") {
        if backend.trim().is_empty() {
            return Err("mykey-auth preflight did not specify a biometric backend.".to_string());
        }
        return Ok(HelperAuthMode::BiometricFirst {
            backends: vec![backend.trim().to_string()],
        });
    }

    if let Some(backends) = stdout.strip_prefix("biometric-group:") {
        let parsed: Vec<String> = backends
            .split(',')
            .map(str::trim)
            .filter(|backend| !backend.is_empty())
            .map(ToString::to_string)
            .collect();
        if parsed.is_empty() {
            return Err(
                "mykey-auth preflight did not specify any biometric backends.".to_string(),
            );
        }
        return Ok(HelperAuthMode::BiometricFirst { backends: parsed });
    }

    if stdout == "security_key" {
        return Ok(HelperAuthMode::SecurityKeyFirst);
    }

    Err(format!(
        "mykey-auth preflight returned an unknown mode: {stdout}"
    ))
}

fn resolve_auth_helper_path() -> Option<&'static str> {
    AUTH_HELPER_CANDIDATES
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).is_file())
}

unsafe fn pam_error(handle: &pam::PamHandle, msg: &str) {
    pam_message(handle, pam_ffi::PAM_ERROR_MSG, msg);
}

unsafe fn pam_info(handle: &pam::PamHandle, msg: &str) {
    pam_message(handle, pam_ffi::PAM_TEXT_INFO, msg);
}

unsafe fn pam_locked_once(handle: &pam::PamHandle, msg: &str) {
    if pam_get_auth_lock_message_state(handle) == AuthLockMessageState::Shown {
        return;
    }

    pam_error(
        handle,
        if msg.is_empty() {
            "MyKey authentication failed."
        } else {
            msg
        },
    );
    let _ = pam_set_auth_lock_message_state(handle, AuthLockMessageState::Shown);
}

pub struct MyKeyModule;

impl PamModule for MyKeyModule {
    fn authenticate(handle: &pam::PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
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

        let resume_pin_fallback =
            unsafe { pam_get_auth_resume_state(handle) == AuthResumeState::PinFallback };

        let mode = if resume_pin_fallback {
            HelperAuthMode::PinOnly
        } else {
            match run_preflight_helper(uid, false) {
                HelperPreflightResult::Ready(mode) => mode,
                HelperPreflightResult::Ignore => return PamReturnCode::Ignore,
                HelperPreflightResult::Locked(msg) => {
                    unsafe {
                        pam_locked_once(handle, &msg);
                    }
                    return PamReturnCode::Auth_Err;
                }
                HelperPreflightResult::Error(msg) => {
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
                    return PamReturnCode::Auth_Err;
                }
            }
        };

        if resume_pin_fallback {
            match run_preflight_helper(uid, true) {
                HelperPreflightResult::Ready(_) => {}
                HelperPreflightResult::Ignore => {
                    unsafe {
                        pam_error(handle, "MyKey PIN fallback is not configured.");
                    }
                    return PamReturnCode::Auth_Err;
                }
                HelperPreflightResult::Locked(msg) => {
                    unsafe {
                        pam_locked_once(
                            handle,
                            if msg.is_empty() {
                                "MyKey PIN fallback is not available."
                            } else {
                                &msg
                            },
                        );
                    }
                    return PamReturnCode::Auth_Err;
                }
                HelperPreflightResult::Error(msg) => {
                    unsafe {
                        pam_error(
                            handle,
                            if msg.is_empty() {
                                "MyKey PIN fallback is not available."
                            } else {
                                &msg
                            },
                        );
                    }
                    return PamReturnCode::Auth_Err;
                }
            }
        }

        let first_result = if resume_pin_fallback {
            prompt_and_verify_pin(handle, uid, "MyKey PIN fallback: ")
        } else {
            match &mode {
                HelperAuthMode::PinOnly => prompt_and_verify_pin(handle, uid, "MyKey PIN: "),
                HelperAuthMode::PasswordFallback => {
                    prompt_and_verify_password(handle, uid, "Linux account password: ")
                }
                HelperAuthMode::BiometricFirst { backends } => {
                    if let Some(message) = biometric_prompt_message(backends) {
                        unsafe {
                            pam_info(handle, &message);
                        }
                    }
                    run_auth_helper(uid, HelperAuthInput::None)
                }
                HelperAuthMode::SecurityKeyFirst => {
                    unsafe {
                        pam_info(
                            handle,
                            "MyKey security-key verification in progress. Touch your enrolled key now.",
                        );
                    }
                    run_auth_helper(uid, HelperAuthInput::None)
                }
            }
        };

        match first_result {
            HelperAuthResult::Success => {
                let _ = unsafe { pam_set_auth_resume_state(handle, AuthResumeState::None) };
                let _ = unsafe {
                    pam_set_auth_lock_message_state(handle, AuthLockMessageState::NotShown)
                };
                PamReturnCode::Success
            }
            HelperAuthResult::AuthFailed => {
                unsafe {
                    pam_error(
                        handle,
                        match mode {
                            HelperAuthMode::PinOnly => "Incorrect MyKey PIN.",
                            HelperAuthMode::PasswordFallback => "Incorrect Linux account password.",
                            HelperAuthMode::BiometricFirst { .. } => {
                                "MyKey biometric authentication failed."
                            }
                            HelperAuthMode::SecurityKeyFirst => {
                                "MyKey security-key authentication failed."
                            }
                        },
                    );
                }
                PamReturnCode::Auth_Err
            }
            HelperAuthResult::NotConfigured => {
                unsafe {
                    pam_error(handle, "MyKey authentication is not configured.");
                }
                PamReturnCode::Auth_Err
            }
            HelperAuthResult::PinFallbackRequired(msg) => {
                let _ = unsafe { pam_set_auth_resume_state(handle, AuthResumeState::PinFallback) };
                if !msg.is_empty() {
                    unsafe {
                        pam_info(handle, &msg);
                    }
                }
                match prompt_and_verify_pin(handle, uid, "MyKey PIN fallback: ") {
                    HelperAuthResult::Success => {
                        let _ = unsafe { pam_set_auth_resume_state(handle, AuthResumeState::None) };
                        let _ = unsafe {
                            pam_set_auth_lock_message_state(handle, AuthLockMessageState::NotShown)
                        };
                        PamReturnCode::Success
                    }
                    HelperAuthResult::AuthFailed => {
                        unsafe {
                            pam_error(handle, "Incorrect MyKey PIN.");
                        }
                        PamReturnCode::Auth_Err
                    }
                    HelperAuthResult::NotConfigured => {
                        let _ = unsafe { pam_set_auth_resume_state(handle, AuthResumeState::None) };
                        unsafe {
                            pam_error(handle, "MyKey PIN fallback is not configured.");
                        }
                        PamReturnCode::Auth_Err
                    }
                    HelperAuthResult::PinFallbackRequired(_) => {
                        unsafe {
                            pam_error(handle, "MyKey PIN fallback did not complete.");
                        }
                        PamReturnCode::Auth_Err
                    }
                    HelperAuthResult::Locked(msg) => {
                        unsafe {
                            pam_locked_once(
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
                    HelperAuthResult::Error(msg) => {
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
            HelperAuthResult::Locked(msg) => {
                if matches!(
                    mode,
                    HelperAuthMode::BiometricFirst { .. } | HelperAuthMode::SecurityKeyFirst
                ) {
                    let _ =
                        unsafe { pam_set_auth_resume_state(handle, AuthResumeState::PinFallback) };
                }
                unsafe {
                    pam_locked_once(
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
            HelperAuthResult::Error(msg) => {
                if matches!(
                    mode,
                    HelperAuthMode::BiometricFirst { .. } | HelperAuthMode::SecurityKeyFirst
                ) {
                    let _ =
                        unsafe { pam_set_auth_resume_state(handle, AuthResumeState::PinFallback) };
                }
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

fn prompt_and_verify_pin(handle: &pam::PamHandle, uid: u32, prompt: &str) -> HelperAuthResult {
    let entered_pin = unsafe {
        match pam_converse(handle, pam_ffi::PAM_PROMPT_ECHO_OFF, prompt) {
            Some(pin) => Zeroizing::new(pin),
            None => return HelperAuthResult::Error("Could not read the MyKey PIN.".to_string()),
        }
    };
    run_auth_helper(uid, HelperAuthInput::Pin(entered_pin.as_bytes()))
}

fn prompt_and_verify_password(handle: &pam::PamHandle, uid: u32, prompt: &str) -> HelperAuthResult {
    let entered_password = unsafe {
        match pam_converse(handle, pam_ffi::PAM_PROMPT_ECHO_OFF, prompt) {
            Some(password) => Zeroizing::new(password),
            None => {
                return HelperAuthResult::Error(
                    "Could not read the Linux account password.".to_string(),
                )
            }
        }
    };
    run_auth_helper(uid, HelperAuthInput::Password(entered_password.as_bytes()))
}

fn biometric_prompt_message(backends: &[String]) -> Option<String> {
    match backends {
        [backend] if backend == "fprintd" => Some(
            "MyKey fingerprint verification in progress. Scan your enrolled finger now."
                .to_string(),
        ),
        [backend] if backend == "howdy" => {
            Some("MyKey face verification in progress. Look at the camera now.".to_string())
        }
        [] => None,
        _ => Some(
            "MyKey biometric verification in progress. Scan your enrolled finger or look at the camera now."
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{biometric_prompt_message, parse_preflight_mode, HelperAuthMode};

    #[test]
    fn parse_preflight_mode_accepts_pin() {
        assert_eq!(
            parse_preflight_mode("pin").expect("pin mode should parse"),
            HelperAuthMode::PinOnly
        );
    }

    #[test]
    fn parse_preflight_mode_accepts_password() {
        assert_eq!(
            parse_preflight_mode("password").expect("password mode should parse"),
            HelperAuthMode::PasswordFallback
        );
    }

    #[test]
    fn parse_preflight_mode_accepts_biometric_backend() {
        assert_eq!(
            parse_preflight_mode("biometric:fprintd").expect("biometric mode should parse"),
            HelperAuthMode::BiometricFirst {
                backends: vec!["fprintd".to_string()],
            }
        );
    }

    #[test]
    fn parse_preflight_mode_accepts_biometric_group() {
        assert_eq!(
            parse_preflight_mode("biometric-group:fprintd,howdy")
                .expect("biometric group mode should parse"),
            HelperAuthMode::BiometricFirst {
                backends: vec!["fprintd".to_string(), "howdy".to_string()],
            }
        );
    }

    #[test]
    fn parse_preflight_mode_accepts_security_key() {
        assert_eq!(
            parse_preflight_mode("security_key").expect("security-key mode should parse"),
            HelperAuthMode::SecurityKeyFirst
        );
    }

    #[test]
    fn biometric_prompt_message_matches_supported_backends() {
        assert_eq!(
            biometric_prompt_message(&["fprintd".to_string()]),
            Some("MyKey fingerprint verification in progress. Scan your enrolled finger now.".to_string())
        );
        assert_eq!(
            biometric_prompt_message(&["howdy".to_string()]),
            Some("MyKey face verification in progress. Look at the camera now.".to_string())
        );
        assert_eq!(
            biometric_prompt_message(&["fprintd".to_string(), "howdy".to_string()]),
            Some(
                "MyKey biometric verification in progress. Scan your enrolled finger or look at the camera now."
                    .to_string()
            )
        );
        assert_eq!(biometric_prompt_message(&[]), None);
    }
}

export_pam_module!(MyKeyModule);
