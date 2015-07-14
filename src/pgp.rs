extern crate rustc_serialize;
use self::rustc_serialize::base64::{FromBase64, FromBase64Error};

use super::PublicKey;

use std::fmt;

#[derive(Debug)]
pub enum PgpError {
    Armor,
    Crc,
    CrcFormat,
    Data,
    Base64(FromBase64Error)
}

impl fmt::Display for PgpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PgpError::Base64(ref err) => err.fmt(f),
            PgpError::Armor => write!(f, "Armored file is malformed"),
            PgpError::Crc => write!(f, "CRC does not match"),
            PgpError::CrcFormat => write!(f, "CRC is not the correct size"),
            PgpError::Data => write!(f, "Expects two base64 blobs")
        }
    }
}

impl From<FromBase64Error> for PgpError {
    fn from(err: FromBase64Error) -> PgpError {
        return PgpError::Base64(err);
    }
}

pub type PgpResult<T> = Result<T, PgpError>;

fn calc_crc(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B704CE;
    for b in data {
        let byte : u32 = (*b) as u32;
        crc ^= byte << 16;
        for _ in 0..8 {
            crc <<= 1;
            if (crc & 0x01000000) == 0x01000000 {
                crc ^= 0x01864CFB;
            }
        }
    }
    crc & 0x00ffffff
}

fn read_armored(armored: &str) -> PgpResult<Vec<u8>> {
    let armor_header = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    let armor_tail = "-----END PGP PUBLIC KEY BLOCK-----";
    let mut lines = armored.lines();

    // Verify the header line
    if lines.next().unwrap() != armor_header {
        return Err(PgpError::Armor);
    }

    // Skip any header values - we don't care about them
    while lines.next().unwrap() != "" {}

    // Parse the body
    let mut data_bytes : Vec<u8> = Vec::new();
    let mut body_read = false;

    while !body_read {
        let line = lines.next().unwrap();
        if line.len() == 0 {
            return Err(PgpError::Armor);
        }
        if line.as_bytes()[0] == b'=' {
            body_read = true;
            let crc_bytes = try!(line[1..].from_base64());
            let crc = ((crc_bytes[0] as u32) << 16) | ((crc_bytes[1] as u32) <<  8) | (crc_bytes[2] as u32);
            if crc_bytes.len() != 3 {
                return Err(PgpError::Armor);
            }
            if crc != calc_crc(data_bytes.as_slice()) {
                return Err(PgpError::Crc);
            }
        } else {
            data_bytes.extend(try!(line.from_base64()));
        }
    }
    if lines.next().unwrap() != armor_tail {
        return Err(PgpError::Armor);
    }
    Ok(data_bytes)
}

pub fn read_public_key(data: &[u8]) -> PgpResult<PublicKey> {
    Ok(PublicKey { n: Vec::new(), e: Vec::new() })
}

pub fn read_armored_public_key(armored: &str) -> PgpResult<PublicKey> {
    let data = try!(read_armored(armored));
    read_public_key(data.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_read_armored_key() {
        read_armored_public_key("-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mI0EVaVSZwEEAJ7Z4u1qOvrKSAPlt7lRrZMXN5T0HWPkKph9+rfN7CZkvA5elhOd
9qHZGJDdN+K73Kd2EiPJmMT31NLx/Z1RzvOElhm7leWQEVUDVV0rd9jarShVHPX7
7Jo/CAOO4jd39TDi5VLpxPGDz0Y7gAOGS8H5WM5+EmTQrkZhER9PPZWLABEBAAG0
IEhlZHdpZyBUZXN0IDxoZWR3aWdAZXhhbXBsZS5jb20+iLcEEwEIACEFAlWlUmcC
GwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQlVIcjvcBDZDIxQP+ItV/Ab9H
aMdkmdkVQk4Wnix/UXA87LTLCS0YAPOyOzzYWiwya0zUpLgqX+ZFIKF4I56KbZ2V
64Via0rZC0G+uHTPzHr+bigaODSGJbxNuOg79HlXz0atNTe+uBw8sdYlIlXqtOSE
xpKn9n2Yu/LO+kcsNm8/rXxB17aTV8eVp+O4jQRVpVJnAQQAucWLPMSj1npBe7Ot
IqPNKqxy2NPEWnXGmlHXGRMaC0I1fIxZ8vaVDYhNvcNjOaEeGUvy4elIYSgclpjG
FU6qsbFfnAkkMmiAwm4bIDrlRRzoO97h9RkFG4cQ8Vo3QUMe9ugY4XcPmXkDQ38p
yysKGckBLkWTA2sbZyLEzQRh+R0AEQEAAYifBBgBCAAJBQJVpVJnAhsMAAoJEJVS
HI73AQ2QjMMEAIrs4jJsFZ+NmHtyaP7PHqt8LbrIMK4hpYanvw/qYmr+u593pnWQ
zDiK2rznv+fzOHrMd2YEJN+iD18GnQygnSuP5IM56obCIulL9GNTcWJa+HDHueVH
xuX+mbgN24NKaEkQUC4EpWD8fJmSGwsSRVlIUE4cLvjbJtXH08ym7vBe
=FxSA
-----END PGP PUBLIC KEY BLOCK-----").unwrap();
    }
}
