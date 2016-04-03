extern crate rustc_serialize;
extern crate byteorder;

use std::io;
use std::fmt;

use gcrypt;
use crypto;

use self::byteorder::{BigEndian,ReadBytesExt};
use self::rustc_serialize::base64::{FromBase64,FromBase64Error};

#[derive(Debug)]
pub enum PgpError {
    Armor,
    Crc,
    DecryptionChecksum,
    Packet(&'static str),
    Unsupported(&'static str),
    Base64(FromBase64Error),
    Byteorder(self::byteorder::Error),
    Gcrypt(gcrypt::error::Error),
}

impl fmt::Display for PgpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PgpError::Armor => write!(f, "Armored file is malformed"),
            PgpError::Crc => write!(f, "CRC does not match"),
            PgpError::DecryptionChecksum => write!(f, "Checksum error while decrypting payload"),
            PgpError::Packet(msg) => write!(f, "Cannot read PGP packet: {}", msg),
            PgpError::Unsupported(msg) => write!(f, "Key uses unsupported format: {}", msg),
            PgpError::Base64(ref err) => err.fmt(f),
            PgpError::Byteorder(ref err) => err.fmt(f),
            PgpError::Gcrypt(ref err) => err.fmt(f),
        }
    }
}

impl From<FromBase64Error> for PgpError {
    fn from(err: FromBase64Error) -> PgpError {
        PgpError::Base64(err)
    }
}

impl From<self::byteorder::Error> for PgpError {
    fn from(err: self::byteorder::Error) -> PgpError {
        PgpError::Byteorder(err)
    }
}

impl From<::std::io::Error> for PgpError {
    fn from(err: ::std::io::Error) -> PgpError {
        PgpError::Byteorder(self::byteorder::Error::Io(err))
    }
}

impl From<gcrypt::error::Error> for PgpError {
    fn from(err: gcrypt::error::Error) -> PgpError {
        PgpError::Gcrypt(err)
    }
}

pub type PgpResult<T> = Result<T, PgpError>;

pub struct PublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub timestamp: u32
}

pub struct PrivateKey {
    pub public: PublicKey,
    pub d: gcrypt::Buffer,
    pub p: gcrypt::Buffer,
    pub q: gcrypt::Buffer,
    pub u: gcrypt::Buffer
}

pub enum Packet {
    PublicKey(PublicKey),
    PrivateKey(PrivateKey)
}

pub trait PgpKey {
    fn fingerprint(&self, Token) -> PgpResult<Vec<u8>>;
}

fn leading_zeros(byte: u8) -> usize {
    if byte & 0xff == 0 {
        8
    } else if byte & 0xfe == 0 {
        7
    } else if byte & 0xfc == 0 {
        6
    } else if byte & 0xf8 == 0 {
        5
    } else if byte & 0xf0 == 0 {
        4
    } else if byte & 0xe0 == 0 {
        3
    } else if byte & 0xc0 == 0 {
        2
    } else if byte & 0x80 == 0 {
        1
    } else {
        0
    }
}

impl PgpKey for PublicKey {
    fn fingerprint(&self, token: Token) -> PgpResult<Vec<u8>> {
        let n_len = self.n.len();
        let e_len = self.e.len();
        let n_mpi_len = n_len*8 - leading_zeros(self.n[0]);
        let e_mpi_len = e_len*8 - leading_zeros(self.e[0]);
        let n_start = 11;
        let n_end = n_start+n_len;
        let e_start = n_end+2;
        let e_end = e_start+e_len;

        let len: usize = 10 + n_len + e_len;
        let mut buf: Vec<u8> = vec![0; len+3];
        buf[0] = 0x99;
        buf[1] = ((len >> 8) & 0xff) as u8;
        buf[2] = (len & 0xff) as u8;
        buf[3] = 4; // V4 packet
        buf[4] = ((self.timestamp >> 24) & 0xff) as u8;
        buf[5] = ((self.timestamp >> 16) & 0xff) as u8;
        buf[6] = ((self.timestamp >> 8) & 0xff) as u8;
        buf[7] = (self.timestamp & 0xff) as u8;
        buf[8] = 1; // RSA key material
        buf[9] = ((n_mpi_len >> 8) & 0xff) as u8;
        buf[10] = (n_mpi_len & 0xff) as u8;
        buf[n_end] = ((e_mpi_len >> 8) & 0xff) as u8;
        buf[n_end+1] = (e_mpi_len & 0xff) as u8;
        for i in 0..n_len {
            buf[n_start+i] = self.n[i];
        }
        for i in 0..e_len {
            buf[e_start+i] = self.e[i];
        }

        assert_eq!(e_end, len+3);

        Ok(try!(crypto::sha1(&buf, token)))
    }
}

impl PgpKey for PrivateKey {
    fn fingerprint(&self, token: Token) -> PgpResult<Vec<u8>> {
        self.public.fingerprint(token)
    }
}

pub type Token = ::gcrypt::Token;

struct StringToKey {
    algorithm: u8,
    salt: Vec<u8>,
    count: usize
}

fn cipher_blocksize(algorithm: u8) -> PgpResult<usize> {
    match algorithm {
        7 => Ok(16),
        _ => Err(PgpError::Unsupported("Key encryption algorithm"))
    }
}

fn cipher_keysize(algorithm: u8) -> PgpResult<usize> {
   match algorithm {
        7 => Ok(16),
        _ => Err(PgpError::Unsupported("Key encryption algorithm"))
    }
}

fn decrypt_data(algorithm: u8, key: &[u8], iv: &[u8], data: &[u8], token: Token) -> PgpResult<gcrypt::Buffer> {
    let (algo,mode) = match algorithm {
        7 => (gcrypt::cipher::CIPHER_AES, gcrypt::cipher::MODE_CFB),
        _ => return Err(PgpError::Unsupported("Key encryption algorithm"))
    };
    let mut cipher = try!(gcrypt::cipher::Cipher::new(token, algo, mode, gcrypt::cipher::FLAG_SECURE));
    try!(cipher.set_key(key));
    try!(cipher.set_iv(iv));
    let mut result = try!(gcrypt::Buffer::new_secure(token, data.len()));
    try!(cipher.decrypt(data, &mut result));
    return Ok(result);
}

fn string_to_key(s2k: StringToKey, password: &[u8], cipher: u8, token: Token) -> PgpResult<gcrypt::Buffer> {
    let needed_bytes = try!(cipher_keysize(cipher));
     let data_len = password.len() + s2k.salt.len();
    let iterations = if s2k.count % data_len == 0 { s2k.count / data_len } else { (s2k.count / data_len) + 1 };
    match s2k.algorithm {
        2 => {
            let algo = gcrypt::digest::MD_SHA1;
            let mut sha = try!(gcrypt::digest::MessageDigest::new(token, algo, gcrypt::digest::FLAG_SECURE));
        
            for _ in 0..iterations {
                sha.write(&s2k.salt);
                sha.write(password);
            }
            let mut result = try!(gcrypt::Buffer::new_secure(token, needed_bytes));
            let digest = sha.get_digest(algo).unwrap();
            for i in 0..needed_bytes {
                result[i] = digest[i];
            }
            Ok(result)
        }
        _ => Err(PgpError::Unsupported("S2K hash algorithm"))
    }
}

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

fn read_bytes_secure<T: io::Read>(data: &mut T, len: usize, token: Token) -> PgpResult<gcrypt::Buffer> {
    let mut result: gcrypt::Buffer = try!(gcrypt::Buffer::new_secure(token, len));
    let mut bytes_read = 0;
    while bytes_read < len {
        let read = try!(data.read(&mut result[bytes_read..]));
        if read == 0 {
            return Err(PgpError::Byteorder(byteorder::Error::UnexpectedEOF));
        }
        bytes_read += read;
    }
    Ok(result)
}

fn read_bignum_secure<T: io::Read>(data: &mut T, token: Token) -> PgpResult<gcrypt::Buffer> {
    let bit_len = try!(data.read_u16::<BigEndian>()) as usize;
    let len = (bit_len + 7) / 8;
    read_bytes_secure(data, len, token)
}

fn read_bytes<T: io::Read>(data: &mut T, len: usize) -> PgpResult<Vec<u8>> {
    let mut result: Vec<u8> = vec![0; len];
    let mut bytes_read = 0;
    while bytes_read < len {
        let read = try!(data.read(&mut result[bytes_read..]));
        if read == 0 {
            return Err(PgpError::Byteorder(byteorder::Error::UnexpectedEOF));
        }
        bytes_read += read;
    }
    Ok(result)
}

fn read_bignum<T: io::Read>(data: &mut T) -> PgpResult<Vec<u8>> {
    let bit_len = try!(data.read_u16::<BigEndian>()) as usize;
    let len = (bit_len + 7) / 8;
    read_bytes(data, len)
}

fn read_s2k<T: io::Read>(data: &mut T) -> PgpResult<StringToKey> {
    let s2k_type = try!(data.read_u8());
    let algorithm =try!(data.read_u8());
    let salt = match s2k_type {
        2 | 3 => try!(read_bytes(data, 8)),
        1 => Vec::new(),
        _ => return Err(PgpError::Unsupported("S2K type"))
    };
    let count = match s2k_type {
        3 => {
            let count = try!(data.read_u8());
            ((16 as usize) + ((count as usize) & 0x0f)) << ((count >> 4) + 6)
        },
        1 | 2 => 1,
        _ => return Err(PgpError::Unsupported("S2K type"))
    };
    Ok(StringToKey { algorithm: algorithm, salt: salt, count: count })
}

fn read_public_key<T: io::Read>(data: &mut T) -> PgpResult<PublicKey> {
    if try!(data.read_u8()) != 4 {
        return Err(PgpError::Packet("Not a v4 key material packet"));
    }

    let timestamp = try!(data.read_u32::<BigEndian>());

    if try!(data.read_u8()) != 1 {
        return Err(PgpError::Packet("Not an RSA key material packet"));
    }

    let n = try!(read_bignum(data));
    let e = try!(read_bignum(data));
    Ok(PublicKey {n: n, e: e, timestamp: timestamp })
}

fn read_private_key<T: io::Read>(data: &mut T, password: &[u8], token: Token) -> PgpResult<PrivateKey> {
    let public = try!(read_public_key(data));
    let convention = try!(data.read_u8());

    // For now only support S2K and unencrypted keys
    let (algorithm, key) = match convention {
        254 | 255 => {
            let algorithm = try!(data.read_u8()); 
            let s2k = try!(read_s2k(data));
            let key = try!(string_to_key(s2k, password, algorithm, token));
            (algorithm, key)
        },
        0 => (0, try!(gcrypt::Buffer::new(token, 0))),
        _ => return Err(PgpError::Unsupported("Non-S2K encrypted keys"))
    };

    let keyblob : gcrypt::Buffer = if convention == 0 {
        let mut key_data = Vec::new();
        try!(data.read_to_end(&mut key_data));
        let mut res = try!(gcrypt::Buffer::new(token, key_data.len()));
        for i in 0..key_data.len() {
            res[i] = key_data[i];
        }
        res
    } else {
        let iv_len = try!(cipher_blocksize(algorithm));
        let iv = try!(read_bytes(data, iv_len));
        let mut encrypted_data: Vec<u8> = Vec::new();
        try!(data.read_to_end(&mut encrypted_data));
        try!(decrypt_data(algorithm, &key, &iv, &encrypted_data, token))
    };
    let sumsize: usize = match convention { 254 => 20, _ => 2 };
    let data_end = keyblob.len() - sumsize;
    match convention {
        254 => {
            let hash = try!(crypto::sha1(&keyblob[..data_end], token));
            if hash != &keyblob[data_end..] {
                return Err(PgpError::DecryptionChecksum)
            }
        }
        _ => return Err(PgpError::Unsupported("2-byte key checksums"))
    }
    let mut keydata = io::Cursor::new(&keyblob[..data_end]);

    let d = try!(read_bignum_secure(&mut keydata, token));
    let p = try!(read_bignum_secure(&mut keydata, token));
    let q = try!(read_bignum_secure(&mut keydata, token));
    let u = try!(read_bignum_secure(&mut keydata, token));
    Ok(PrivateKey { public: public, d: d, p: p, q: q, u: u })
}

fn read_armored(armored: &str) -> PgpResult<Vec<u8>> {
    let armor_headers = ["-----BEGIN PGP PUBLIC KEY BLOCK-----","-----BEGIN PGP PRIVATE KEY BLOCK-----"];
    let armor_tails = ["-----END PGP PUBLIC KEY BLOCK-----","-----END PGP PRIVATE KEY BLOCK-----"];
    let mut lines = armored.lines();

    // Verify the header line
    let header_line = lines.next().unwrap();
    let packet_type_idx = match armor_headers.iter().position(|&x| x == header_line) {
        Some(idx) => idx,
        None => return Err(PgpError::Armor)
    };

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
            if crc != calc_crc(&data_bytes) {
                return Err(PgpError::Crc);
            }
        } else {
            data_bytes.extend(try!(line.from_base64()));
        }
    }
    if lines.next().unwrap() != armor_tails[packet_type_idx] {
        return Err(PgpError::Armor);
    }
    Ok(data_bytes)
}

pub fn read_packet(data: &[u8], password: Option<&[u8]>, token: Token) -> PgpResult<Packet> {
    let tag_byte = data[0];
    let tag = (tag_byte >> 2) & 0x0f;
    let len_type = tag_byte & 0x03;
    let style = (tag_byte >> 6) & 0x01;
    let check = (tag_byte >> 7) & 0x01;

    if check == 0 {
        return Err(PgpError::Packet("Bad check bit"));
    }

    if style != 0 {
        return Err(PgpError::Unsupported("New-style packet length"));
    }

    if len_type == 3 {
        return Err(PgpError::Unsupported("Indeterminate length packets"));
    }

    let len_bytes = 1 << len_type;
    let mut len: usize = 0;
    for byte in 0..len_bytes {
        len = len << 8;
        len |= data[1+byte] as usize;
    }

    let mut cursor = io::Cursor::new(&data[1+len_bytes..1+len_bytes+len]);

    let pword = match password {
        Some(string) => string,
        None => "".as_bytes()
    };

    match tag {
        5 => Ok(Packet::PrivateKey(try!(read_private_key(&mut cursor, pword, token)))),
        6 => Ok(Packet::PublicKey(try!(read_public_key(&mut cursor)))),
        _ => Err(PgpError::Unsupported("Packet type"))
    }
}

pub fn read_armored_packet(armored: &str, password: Option<&[u8]>, token: Token) -> PgpResult<Packet> {
    let data = try!(read_armored(armored));
    read_packet(&data, password, token)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use super::super::tests::*;

    #[test]
    fn can_read_armored_public_key() {
        let token = ::gcrypt::init(|mut gcry| {
            gcry.enable_secmem(16384).unwrap();
        });
        let packet = read_armored_packet(PUBKEY, None, token).unwrap();
        let pubkey = match packet {
            Packet::PublicKey(key) => key,
            _ => unreachable!()
        };

        assert_eq!(pubkey.n, EXPECTED_N.to_owned());
        assert_eq!(pubkey.e, EXPECTED_E.to_owned());
        assert_eq!(pubkey.fingerprint(token).unwrap(), EXPECTED_FINGERPRINT.to_owned());
    }

    #[test]
    fn can_read_armored_private_key() {
        let token = ::gcrypt::init(|mut gcry| {
            gcry.enable_secmem(16384).unwrap();
        });
        let packet = read_armored_packet(PRIVKEY, Some("password".as_bytes()), token).unwrap();
        let privkey = match packet {
            Packet::PrivateKey(key) => key,
            _ => unreachable!()
        };

        assert_eq!(privkey.public.n, EXPECTED_N.to_owned());
        assert_eq!(privkey.public.e, EXPECTED_E.to_owned());
        assert_eq!(privkey.fingerprint(token).unwrap(), EXPECTED_FINGERPRINT);
        assert_eq!(privkey.d.as_bytes().to_owned(), EXPECTED_D.to_owned());
        assert_eq!(privkey.p.as_bytes().to_owned(), EXPECTED_P.to_owned());
        assert_eq!(privkey.q.as_bytes().to_owned(), EXPECTED_Q.to_owned());
        assert_eq!(privkey.u.as_bytes().to_owned(), EXPECTED_U.to_owned());
    }

}
