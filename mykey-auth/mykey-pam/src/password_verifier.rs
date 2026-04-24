use std::ffi::{CStr, CString};

use pam::{Client, Conversation, PamError, PamReturnCode};
use zeroize::Zeroizing;

pub const PAM_SERVICE: &str = "mykey-elevated-auth";

pub fn uid_to_username(uid: u32) -> Option<String> {
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
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
            let name = unsafe { CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned();
            return Some(name);
        }
        if rc == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return None;
    }
}

pub fn verify_password(username: &str, password: &str) -> Result<(), PamReturnCode> {
    let mut client = Client::with_conversation(
        PAM_SERVICE,
        FixedPasswordConversation::new(username.to_string(), password.to_string()),
    )
    .map_err(|PamError(code)| code)?;
    client.authenticate().map_err(|PamError(code)| code)
}

pub fn is_auth_failure(code: PamReturnCode) -> bool {
    matches!(
        code,
        PamReturnCode::Auth_Err
            | PamReturnCode::Perm_Denied
            | PamReturnCode::Cred_Insufficient
            | PamReturnCode::Authinfo_Unavail
            | PamReturnCode::User_Unknown
            | PamReturnCode::MaxTries
            | PamReturnCode::AuthTok_Err
            | PamReturnCode::New_Authtok_Reqd
            | PamReturnCode::Acct_Expired
    )
}

struct FixedPasswordConversation {
    login: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl FixedPasswordConversation {
    fn new(login: String, password: String) -> Self {
        Self {
            login: Zeroizing::new(login),
            password: Zeroizing::new(password),
        }
    }
}

impl Conversation for FixedPasswordConversation {
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.login.as_str()).map_err(|_| ())
    }

    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.password.as_str()).map_err(|_| ())
    }

    fn info(&mut self, _msg: &CStr) {}

    fn error(&mut self, _msg: &CStr) {}
}
