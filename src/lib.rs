use std::fmt;

mod keybase;
mod pgp;

use self::pgp::PgpError;

#[derive(Debug)]
pub enum HedwigError {
    Pgp(PgpError)
}

impl fmt::Display for HedwigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HedwigError::Pgp(ref err) => err.fmt(f)
        }
    }
}

impl From<PgpError> for HedwigError {
    fn from(err: PgpError) -> HedwigError {
        return HedwigError::Pgp(err);
    }
}

pub type HedwigResult<T> = Result<T, HedwigError>;

pub fn fetch_public_key(name: String) -> HedwigResult<pgp::PublicKey> {
    Ok(try!(pgp::read_pubkey(keybase::fetch_user(name).public_key())))
}