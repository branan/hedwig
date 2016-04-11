mod api;

use gcrypt;
use hyper;
use rustc_serialize::base64;
use rustc_serialize::hex;
use rustc_serialize::json;

use crypto;

use std::fmt;
use std::io;


use rustc_serialize::base64::FromBase64;
use rustc_serialize::hex::FromHex;
use rustc_serialize::hex::ToHex;

#[derive(Debug)]
pub enum KeybaseError {
    Http(String),
    Api(api::Status),
    FromBase64(base64::FromBase64Error),
    FromHex(hex::FromHexError),
    Gcrypt(gcrypt::error::Error),
    Hyper(hyper::Error),
    Io(io::Error),
    Json(json::DecoderError),
}

impl From<api::Status> for KeybaseError {
    fn from(err: api::Status) -> KeybaseError {
        KeybaseError::Api(err)
    }
}

impl From<base64::FromBase64Error> for KeybaseError {
    fn from(err: base64::FromBase64Error) -> KeybaseError {
        KeybaseError::FromBase64(err)
    }
}

impl From<hex::FromHexError> for KeybaseError {
    fn from(err: hex::FromHexError) -> KeybaseError {
        KeybaseError::FromHex(err)
    }
}

impl From<gcrypt::error::Error> for KeybaseError {
    fn from(err: gcrypt::error::Error) -> KeybaseError {
       KeybaseError::Gcrypt(err)
    }
}

impl From<hyper::Error> for KeybaseError {
    fn from(err: hyper::Error) -> KeybaseError {
        KeybaseError::Hyper(err)
    }
}

impl From<io::Error> for KeybaseError {
    fn from(err: io::Error) -> KeybaseError {
        KeybaseError::Io(err)
    }
}

impl From<json::DecoderError> for KeybaseError {
    fn from(err: json::DecoderError) -> KeybaseError {
        KeybaseError::Json(err)
    }
}

impl fmt::Display for KeybaseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeybaseError::Http(ref msg) => write!(f, "Keybase API Error: {}", msg),
            KeybaseError::Api(ref err) => match err.desc.as_ref() {
                Some(ref desc) => write!(f, "Keybase API error: {} ({})", desc, err.name),
                None => write!(f, "Keybase API error: {}", err.name),
            },
            KeybaseError::FromBase64(ref err) => err.fmt(f),
            KeybaseError::FromHex(ref err) => err.fmt(f),
            KeybaseError::Gcrypt(ref err) => err.fmt(f),
            KeybaseError::Hyper(ref err) => err.fmt(f),
            KeybaseError::Io(ref err) => err.fmt(f),
            KeybaseError::Json(ref err) => err.fmt(f),
        }
    }
}

pub type KeybaseResult<T> = Result<T, KeybaseError>;

#[allow(dead_code)]
pub struct Keybase {
    session: String,
    csrf_token: String,
}

impl Keybase {
    pub fn login(user: &str, password: &str, token: gcrypt::Token) -> KeybaseResult<Keybase> {
        let getsalt = try!(api::getsalt(user));
        let salt = &getsalt.salt.unwrap();
        let login_session = &getsalt.login_session.unwrap();
        let salt_bytes = try!(salt.from_hex());
        let mut pwh = vec![0; 224];
        try!(crypto::scrypt(password, &salt_bytes, &mut pwh, token));

        let session = try!(login_session.from_base64());
        let hmac_pwh = try!(crypto::hmac_sha512(&session, &pwh[192..224], token));
        let key = hmac_pwh.to_hex();
        let login = try!(api::login(user, &key, login_session));
        Ok(Keybase{session : login.session.unwrap(), csrf_token: login.csrf_token.unwrap()})
    }
}

#[cfg(test)]
mod tests {
    use gcrypt;
    use super::*;
    use std::env;

    #[test]
    #[allow(unused_variables)]
    fn can_login() {
        let token = gcrypt::init(|mut gcry| {
            gcry.enable_secmem(16384).unwrap();
        });
        let username = &env::var("HEDWIG_TEST_KEYBASE_USERNAME").unwrap();
        let password = &env::var("HEDWIG_TEST_KEYBASE_PASSWORD").unwrap();
        let keybase_session = Keybase::login(&username, &password, token).unwrap();
    }
}
