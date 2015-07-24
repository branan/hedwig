extern crate rustc_serialize;
extern crate byteorder;

use std::io;
use std::fmt;

use self::byteorder::{BigEndian,ReadBytesExt};
use self::rustc_serialize::base64::{FromBase64,FromBase64Error};

use super::crypto;

#[derive(Debug)]
pub enum PgpError {
    Armor,
    Crc,
    DecryptionChecksum,
    Packet(&'static str),
    Unsupported(&'static str),
    Base64(FromBase64Error),
    Byteorder(self::byteorder::Error),
}

impl fmt::Display for PgpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PgpError::Base64(ref err) => err.fmt(f),
            PgpError::Byteorder(ref err) => err.fmt(f),
            PgpError::Unsupported(msg) => write!(f, "Key uses unsupported packet format: {}", msg),
            PgpError::Packet(msg) => write!(f, "Cannot read PGP packet: {}", msg),
            PgpError::Armor => write!(f, "Armored file is malformed"),
            PgpError::Crc => write!(f, "CRC does not match"),
            PgpError::DecryptionChecksum => write!(f, "Checksum error while decrypting payload")
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

pub type PgpResult<T> = Result<T, PgpError>;

pub struct PublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub timestamp: u32,
}

pub struct PrivateKey {
    pub public: PublicKey,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub u: Vec<u8>
}

pub trait PgpKey {
    fn fingerprint(&self) -> [u8; 20];
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
    fn fingerprint(&self) -> [u8; 20] {
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

        let mut sha = crypto::SHA1::new();
        sha.update(&buf);
        sha.finalize()
    }
}

impl PgpKey for PrivateKey {
    fn fingerprint(&self) -> [u8; 20] {
        self.public.fingerprint()
    }
}

pub enum Packet {
    PublicKey(PublicKey),
    PrivateKey(PrivateKey)
}

impl Packet {
    pub fn public_key(self) -> Option<PublicKey> {
        match self {
            Packet::PublicKey(key) => Some(key),
            _ => None
        }
    }

    pub fn private_key(self) -> Option<PrivateKey> {
        match self {
            Packet::PrivateKey(key) => Some(key),
            _ => None
        }
    }
}

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

fn decrypt_data(algorithm: u8, key: &[u8], iv: &[u8], data: &[u8]) -> PgpResult<Vec<u8>> {
    match algorithm {
        7 => {
            let mut aes = crypto::AES::new(key);
            Ok(aes.cfb_decrypt(data, iv))
        },
        _ => Err(PgpError::Unsupported("Key encryption algorithm"))
    }
}

fn string_to_key(s2k: StringToKey, password: &str, cipher: u8) -> PgpResult<Vec<u8>> {
    let needed_bytes = try!(cipher_keysize(cipher));
    let pword : Vec<u8> = s2k.salt.iter().chain(password.as_bytes().iter()).cloned().collect();
    let iterations = if s2k.count % pword.len() == 0 { s2k.count / pword.len() } else { (s2k.count / pword.len()) + 1 };
    match s2k.algorithm {
        2 => {
            let mut sha = crypto::SHA1::new();
            for _ in 0..iterations {
                sha.update(&pword);
            }
            Ok(sha.finalize()[0..needed_bytes].to_owned())
        }
        _ => return Err(PgpError::Unsupported("S2K hash algorithm"))
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

fn read_private_key<T: io::Read>(data: &mut T,password: &str) -> PgpResult<PrivateKey> {
    let public = try!(read_public_key(data));
    let convention = try!(data.read_u8());

    // For now only support S2K and unencrypted keys
    let algotuple: (u8, Vec<u8>) = match convention {
        254 | 255 => {
            let algorithm = try!(data.read_u8()); 
            let s2k = try!(read_s2k(data));
            let key = try!(string_to_key(s2k, password, algorithm));
            (algorithm, key)
        },
        0 => (0, Vec::new()),
        _ => return Err(PgpError::Unsupported("Non-S2K encrypted keys"))
    };

    let algorithm = algotuple.0;
    let key = algotuple.1;
    let mut keyblob: Vec<u8> = Vec::new();

    if convention == 0 {
        try!(data.read_to_end(&mut keyblob));
    } else {
        let iv_len = try!(cipher_blocksize(algorithm));
        let iv = try!(read_bytes(data, iv_len));
        let mut encrypted_data: Vec<u8> = Vec::new();
        try!(data.read_to_end(&mut encrypted_data));
        keyblob = try!(decrypt_data(algorithm, &key, &iv, &encrypted_data));
    }

    let sumsize: usize = match convention { 254 => 20, _ => 2 };
    let data_end = keyblob.len() - sumsize;
    match convention {
        254 => {
            let mut sha = crypto::SHA1::new();
            sha.update(&keyblob[..data_end]);
            if sha.finalize() != &keyblob[data_end..] {
                return Err(PgpError::DecryptionChecksum)
            }
        }
        _ => return Err(PgpError::Unsupported("2-byte key checksums"))
    }
    let mut keydata = io::Cursor::new(&keyblob[..data_end]);

    let d = try!(read_bignum(&mut keydata));
    let p = try!(read_bignum(&mut keydata));
    let q = try!(read_bignum(&mut keydata));
    let u = try!(read_bignum(&mut keydata));
    Ok(PrivateKey { public: public, d: d, p: p, q: q, u: u })
}

pub fn read_packet(data: &[u8], password: Option<&str>) -> PgpResult<Packet> {
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
        None => ""
    };

    match tag {
        5 => Ok(Packet::PrivateKey(try!(read_private_key(&mut cursor, pword)))),
        6 => Ok(Packet::PublicKey(try!(read_public_key(&mut cursor)))),
        _ => Err(PgpError::Unsupported("Packet type"))
    }
}

pub fn read_armored_packet(armored: &str, password: Option<&str>) -> PgpResult<Packet> {
    let data = try!(read_armored(armored));
    read_packet(&data, password)
}

#[cfg(test)]
pub mod tests {
    use super::*;

       pub const PUBKEY: &'static str ="-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mI0EVabG/AEEAKa4oAH9xQdSo9SAFmETpDpxsyvTTnwmqxhYDxllpqY1ZcEIiGB1
URtCfvy1TFozi0rJHi/QPO2wdR+xvrpIi1d+9mJQKD2VhSrp18oio3/xqxoKf7Qc
vzHGF46eCrMDn3LAXwCaQOJRY9lk4bUKjs5aHz6KAtC7XS9EddX5/5S/ABEBAAG0
IEhlZHdpZyBUZXN0IDxoZWR3aWdAZXhhbXBsZS5jb20+iLcEEwEIACEFAlWmxvwC
GwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQgOC+ukVe0tNu/QP/UOS+Ybx7
ED61M9Aa4jSCkrPayEgStqk+ZPct6M0J3QiyVAnoXrDn8jPzroV0zb6zr06XGqYC
tf6qQmTcAO4dJSfT5BQ8dRUDWG8zM0qOU2ey1r6K3/SGGmZXozSA/b6OAJijfW48
+rVctsNvDvhl/52x1XItrIxnTtw2YvRe20u4jQRVpsb8AQQAqa+HkYNTcpaLeahh
klg47XfExIWbYq2K/bmhMHLQFJ5v+5ySAFXdfMTTXDm9ghfvgmpALBa/5tj3P5Oe
eHqnIglGzlw2E/GjGs/w826Q3Co5GmhJK+8ckKuFlboRa4zckdEQELfNe8L95OyG
nv90JPRzKjtMttgDc7OxNxeheN0AEQEAAYifBBgBCAAJBQJVpsb8AhsMAAoJEIDg
vrpFXtLTyl8D/j7dR4xtQz68wvrhl6yxdVnEtIcL7pAwl4fwUWBszBnIQU+sIOxL
DuS2x8fODgRlJAxPGtGEEGLJ517lbS+oxqhTX4Z8qJXmPruXeUevUltlmJZ5Vi8F
nSCSFbU63GPL7fOIuFFug7O9rcQen+aaDNZyd5SznwxVUStGEBDEockp
=s6n/
-----END PGP PUBLIC KEY BLOCK-----";

    pub const PRIVKEY: &'static str = "-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2

lgAAAgYEVabG/AEEAKa4oAH9xQdSo9SAFmETpDpxsyvTTnwmqxhYDxllpqY1ZcEI
iGB1URtCfvy1TFozi0rJHi/QPO2wdR+xvrpIi1d+9mJQKD2VhSrp18oio3/xqxoK
f7QcvzHGF46eCrMDn3LAXwCaQOJRY9lk4bUKjs5aHz6KAtC7XS9EddX5/5S/ABEB
AAH+BwMC6yKaPW6t1KDr4DT7PhWI2Zgq7mL3Z7j6l/1mDHSrKrfMXHgcQmMWooD0
jig5v69jkhfsxr/UFG83zlH76Gs1P8G9lN8MJHY5fpJV46PERXwodRnIgCKvq6DH
vcSqzb+rYPbl5oSqDssaqOMroaFk7DOPyVF2rHF/2GP8zY1bWdQvligc+ZaqJQnW
jRtN2JZj5ZEbCVxXzFyDTn83393Uzy13dH+cJrgp3re2IRqRXvYSAHhxG2m6hBNE
c/GwRe1ZEffZwazCdfYjiShKFMtqWuA+8L/0AvoNdSEXUWsGAX941Rb+IwmK+/8O
tlHI6PW28tfuRUPunkTVHo28Ltfcb5MVtu6NURyl6SKI0bqB05XG9EvFi2sVHbs1
1+MVWI6gog69Ju5CcRCKPxyEqICBMYVW79ec2GeURjNBiFFiN0uXLqDG3PCMEk/V
YiM55r6voRRc80S4mXvo8phkmSosfcgWZhJnAD8zgjxeyF8V567/ExBF0bQgSGVk
d2lnIFRlc3QgPGhlZHdpZ0BleGFtcGxlLmNvbT6ItwQTAQgAIQUCVabG/AIbAwUL
CQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRCA4L66RV7S0279A/9Q5L5hvHsQPrUz
0BriNIKSs9rISBK2qT5k9y3ozQndCLJUCehesOfyM/OuhXTNvrOvTpcapgK1/qpC
ZNwA7h0lJ9PkFDx1FQNYbzMzSo5TZ7LWvorf9IYaZlejNID9vo4AmKN9bjz6tVy2
w28O+GX/nbHVci2sjGdO3DZi9F7bS54AAAIGBFWmxvwBBACpr4eRg1Nylot5qGGS
WDjtd8TEhZtirYr9uaEwctAUnm/7nJIAVd18xNNcOb2CF++CakAsFr/m2Pc/k554
eqciCUbOXDYT8aMaz/DzbpDcKjkaaEkr7xyQq4WVuhFrjNyR0RAQt817wv3k7Iae
/3Qk9HMqO0y22ANzs7E3F6F43QARAQAB/gcDAjZ0faZ+S1VA66PeQCcCV1JfXo1X
zW+/h2quL8NnzyBfX+5vsiUhW5udvgKiNiHDvuG/8nnyxYjLCfndsiPnUNdhoB7S
ZBYhQwqSFujWm2rvLwbyyu0fxYhtcqVXhnJA7hjx6heQplbB5n3h2UkXHah41MKf
+1JGhOIPFMtLg9TadmrJcxApeBm86pzhFd5wCbCSM0DM3GIUyXNR5cq4Wq/E14Lp
OlQae7vMdmOBSI4kTPgqOUVGZSKpDxLnemYpeCgvwiDfSH4fmIeL6aIXSGgK1UN7
M0nzq+LpKrJq1k7LuDjWWwKGOKyrXBMzXDtgi5I2FLp0YUXTxQIT3Iii33yYce3m
X0uPEiPzzJ0zljT/mgzZ/I7t6yox1nWguH+WsRmt2w83KNg/UsjEQG63RfshCQb+
4Yfv7MT6loDw77aESVrg1KYZBEEEbEbZAUAQpBHyPkdnruYlhPuWcqS0TWcC3dkj
1NhNRIQAjbr3TkBQ5xxRzz+InwQYAQgACQUCVabG/AIbDAAKCRCA4L66RV7S08pf
A/4+3UeMbUM+vML64ZessXVZxLSHC+6QMJeH8FFgbMwZyEFPrCDsSw7ktsfHzg4E
ZSQMTxrRhBBiyede5W0vqMaoU1+GfKiV5j67l3lHr1JbZZiWeVYvBZ0gkhW1Otxj
y+3ziLhRboOzva3EHp/mmgzWcneUs58MVVErRhAQxKHJKQ==
=tKsK
-----END PGP PRIVATE KEY BLOCK-----";


    const EXPECTED_N: [u8; 128] = [166, 184, 160, 1, 253, 197, 7, 82, 163, 212, 128, 22, 97, 19, 164, 58, 113, 179, 43, 211, 78, 124, 38, 171, 24, 88, 15, 25, 101, 166, 166, 53, 101, 193, 8, 136, 96, 117, 81, 27, 66, 126, 252, 181, 76, 90, 51, 139, 74, 201, 30, 47, 208, 60, 237, 176, 117, 31, 177, 190, 186, 72, 139, 87, 126, 246, 98, 80, 40, 61, 149, 133, 42, 233, 215, 202, 34, 163, 127, 241, 171, 26, 10, 127, 180, 28, 191, 49, 198, 23, 142, 158, 10, 179, 3, 159, 114, 192, 95, 0, 154, 64, 226, 81, 99, 217, 100, 225, 181, 10, 142, 206, 90, 31, 62, 138, 2, 208, 187, 93, 47, 68, 117, 213, 249, 255, 148, 191];
    const EXPECTED_E: [u8; 3] = [1, 0, 1];
    const EXPECTED_D: [u8; 128] = [14, 170, 192, 92, 220, 123, 232, 100, 131, 72, 47, 10, 136, 248, 198, 226, 99, 93, 77, 86, 54, 25, 226, 246, 251, 89, 199, 222, 70, 156, 142, 19, 181, 131, 113, 98, 58, 6, 40, 31, 251, 78, 27, 162, 65, 120, 207, 255, 9, 145, 190, 231, 154, 236, 185, 70, 100, 79, 104, 254, 43, 250, 52, 211, 213, 207, 54, 226, 66, 24, 45, 130, 148, 17, 34, 169, 143, 99, 90, 180, 243, 197, 134, 7, 28, 215, 116, 105, 164, 114, 188, 66, 116, 187, 231, 68, 134, 7, 98, 148, 171, 170, 30, 23, 86, 117, 71, 116, 205, 211, 85, 242, 82, 131, 231, 89, 191, 200, 235, 236, 82, 95, 158, 3, 116, 10, 61, 69];
    const EXPECTED_P: [u8; 64] = [195, 217, 45, 107, 236, 207, 2, 12, 208, 192, 85, 223, 99, 183, 151, 184, 73, 186, 177, 248, 102, 243, 204, 243, 84, 31, 186, 202, 54, 130, 133, 224, 87, 175, 141, 177, 252, 95, 77, 149, 236, 237, 197, 137, 81, 136, 118, 233, 27, 17, 169, 223, 104, 47, 161, 145, 148, 192, 151, 31, 43, 72, 252, 93];
    const EXPECTED_Q: [u8; 64] = [217, 237, 73, 200, 174, 128, 175, 252, 176, 103, 83, 192, 155, 35, 35, 153, 40, 18, 155, 20, 197, 170, 3, 0, 90, 232, 25, 147, 23, 73, 130, 253, 59, 180, 139, 151, 233, 226, 122, 217, 14, 106, 61, 26, 31, 224, 174, 8, 179, 249, 206, 58, 21, 77, 248, 140, 177, 229, 63, 169, 175, 45, 227, 203];
    const EXPECTED_U: [u8; 64] = [180, 25, 41, 203, 183, 237, 80, 206, 246, 244, 84, 142, 239, 133, 17, 110, 159, 86, 128, 110, 13, 79, 51, 205, 127, 168, 203, 28, 187, 228, 186, 57, 171, 155, 172, 81, 52, 187, 240, 133, 197, 17, 139, 184, 150, 122, 49, 102, 194, 167, 34, 187, 129, 3, 72, 231, 161, 243, 193, 226, 167, 159, 156, 243];
    const EXPECTED_FINGERPRINT: [u8; 20] = [207, 88, 186, 9, 9, 128, 178, 190, 109, 45, 4, 61, 128, 224, 190, 186, 69, 94, 210, 211];

    #[test]
    fn can_read_armored_public_key() {
        let packet = read_armored_packet(PUBKEY, None).unwrap();
        let pubkey = match packet {
            Packet::PublicKey(key) => key,
            _ => unreachable!()
        };

        assert_eq!(pubkey.n, EXPECTED_N.to_owned());
        assert_eq!(pubkey.e, EXPECTED_E.to_owned());
        assert_eq!(pubkey.fingerprint(), EXPECTED_FINGERPRINT);
    }

    #[test]
    fn can_read_armored_private_key() {
        let packet = read_armored_packet(PRIVKEY, Some("password")).unwrap();
        let privkey = match packet {
            Packet::PrivateKey(key) => key,
            _ => unreachable!()
        };

        assert_eq!(privkey.public.n, EXPECTED_N.to_owned());
        assert_eq!(privkey.public.e, EXPECTED_E.to_owned());
        assert_eq!(privkey.public.fingerprint(), EXPECTED_FINGERPRINT);
        assert_eq!(privkey.d, EXPECTED_D.to_owned());
        assert_eq!(privkey.p, EXPECTED_P.to_owned());
        assert_eq!(privkey.q, EXPECTED_Q.to_owned());
        assert_eq!(privkey.u, EXPECTED_U.to_owned());
    }
}
