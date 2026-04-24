use std::ffi::{CStr, CString};

use pam::{Client, Conversation, PamError, PamReturnCode};

pub const PAM_SERVICE: &str = "mykey-security-key-auth";

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

pub fn authenticate_user(username: &str) -> Result<(), PamReturnCode> {
    let mut client = Client::with_conversation(
        PAM_SERVICE,
        SecurityKeyConversation::new(username.to_string()),
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

struct SecurityKeyConversation {
    login: String,
}

impl SecurityKeyConversation {
    fn new(login: String) -> Self {
        Self { login }
    }
}

impl Conversation for SecurityKeyConversation {
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.login.as_str()).map_err(|_| ())
    }

    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()> {
        let prompt = msg
            .to_str()
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("Security-key PIN: ");
        let value = rpassword::prompt_password(prompt).map_err(|_| ())?;
        CString::new(value).map_err(|_| ())
    }

    fn info(&mut self, msg: &CStr) {
        eprintln!("{}", msg.to_string_lossy());
    }

    fn error(&mut self, msg: &CStr) {
        eprintln!("{}", msg.to_string_lossy());
    }
}
