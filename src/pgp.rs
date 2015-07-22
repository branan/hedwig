extern crate rustc_serialize;
extern crate byteorder;
use std::io::Cursor;
use std::io::Read;
use std;
use std::fmt;

use self::byteorder::{BigEndian,ReadBytesExt};
use self::rustc_serialize::base64::{FromBase64, FromBase64Error};

use super::{PublicKey, PrivateKey};
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

impl From<std::io::Error> for PgpError {
    fn from(err: std::io::Error) -> PgpError {
        PgpError::Byteorder(self::byteorder::Error::Io(err))
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

pub fn read_bignum<T: Read>(data: &mut T) -> PgpResult<Vec<u8>> {
    let len = (try!(data.read_u16::<BigEndian>()) as usize + 7) / 8;
    println!("{}", len);
    let mut result: Vec<u8> = vec![0; len];
    let mut bytes_read = 0;
    while bytes_read < len {
        let read = try!(data.read(&mut result[bytes_read..]));
        if read == 0 {
            return Err(PgpError::Byteorder(self::byteorder::Error::UnexpectedEOF));
        }
        bytes_read += read;
    }
    Ok(result)
}
pub fn read_public_key<T: Read>(data : &mut T) -> PgpResult<PublicKey> {
    let tag_byte = try!(data.read_u8());
    let tag = (tag_byte >> 2) & 0x0f;
    let len_type = tag_byte & 0x03;
    let style = (tag_byte >> 6) & 0x01;
    let check = (tag_byte >> 7) & 0x01;
    let mut next_idx = 1;

    if check == 0 {
        return Err(PgpError::Packet("Bad check bit"));
    }

    if style != 0 {
        return Err(PgpError::Unsupported("New-style packet length"));
    }

    if tag != 6 {
        return Err(PgpError::Packet("not a public key"));
    }

    if len_type == 3 {
        return Err(PgpError::Unsupported("Indeterminate length packets"));
    }

    let len_bytes = 1 << len_type;
    for _ in 0..len_bytes {
        // we ignore the size data (for now)
        try!(data.read_u8());
    }

    if try!(data.read_u8()) != 4 {
        return Err(PgpError::Packet("Not a v4 key material packet"));
    }

    // skip the timestamp
    try!(data.read_u32::<BigEndian>());

    if try!(data.read_u8()) != 1 {
        return Err(PgpError::Packet("Not an RSA key material packet"));
    }

    let n = try!(read_bignum(data));
    let e = try!(read_bignum(data));
    Ok(PublicKey {n: n, e: e })
}

pub fn read_armored_public_key(armored: &str) -> PgpResult<PublicKey> {
    let data = try!(read_armored(armored));
    let mut cursor = Cursor::new(data);
    read_public_key(&mut cursor)
}

pub fn read_private_key(data: &[u8], password: Option<&str>) -> PgpResult<PrivateKey> {
    // TODO: This copies a bunch of logic from read_public_key. Each
    // of these chunks of logic should be made proper readers that can
    // consume a stream of bytes and do something with it.
    //
    // Tracking offsets by hand throughout the body of the function is crazy.
    let tag = (data[0] >> 2) & 0x0f;
    let len_type = data[0] & 0x03;
    let style = (data[0] >> 6) & 0x01;
    let check = (data[0] >> 7) & 0x01;
    let mut next_idx = 1;

    if check == 0 {
        return Err(PgpError::Packet("Bad check bit"));
    }

    if style != 0 {
        return Err(PgpError::Unsupported("New-style packet length"));
    }

    if tag != 5 {
        return Err(PgpError::Packet("not a public key"));
    }

    if len_type == 3 {
        return Err(PgpError::Unsupported("Indeterminate length packets"));
    }

    let len_bytes = 1 << len_type;
    let mut packet_length :usize = 0;
    for _ in 0..len_bytes {
        packet_length = packet_length << 8;
        packet_length |= data[next_idx] as usize;
        next_idx += 1;
    }

    let packet_data = &data[next_idx..(next_idx+packet_length)];

    if packet_data[0] != 4 {
        return Err(PgpError::Packet("Not a v4 key material packet"));
    }

    if packet_data[5] != 1 {
        return Err(PgpError::Packet("Not an RSA key material packet"));
    }

    let n_mpi_start = 8;
    let n_mpi_len = (((packet_data[6] as usize) << 8 | packet_data[7] as usize)+7) / 8;
    let n_mpi_end = n_mpi_start + n_mpi_len;
    let e_mpi_start = n_mpi_end + 2;
    let e_mpi_len = (((packet_data[n_mpi_end] as usize) << 8 | packet_data[n_mpi_end+1] as usize)+7) /8;
    let e_mpi_end = e_mpi_start + e_mpi_len;

    let encryption_convention = packet_data[e_mpi_end];
    if encryption_convention != 254 {
        return Err(PgpError::Unsupported("Only type 254 s2k convention is supported"));
    }

    let encryption_algorithm = packet_data[e_mpi_end+1];
    if encryption_algorithm != 7 {
        return Err(PgpError::Unsupported("Only 128-bit AES encryption is supported"));
    }

    let s2k_type = packet_data[e_mpi_end+2];
    if s2k_type != 3 {
        return Err(PgpError::Unsupported("Only iterated/salted S2K is supported"));
    }

    let s2k_hash = packet_data[e_mpi_end+3];
    if s2k_hash != 2 {
        return Err(PgpError::Unsupported("Only SHA1 s2k is supported"));
    }
    let s2k_salt = &packet_data[e_mpi_end+4..e_mpi_end+12];
    let s2k_c = packet_data[e_mpi_end+12];
    let s2k_count = ((16 as usize) + ((s2k_c as usize) & 0x0f)) << ((s2k_c >>4) + 6);
    let pword : Vec<u8> = s2k_salt.iter().chain(password.unwrap().as_bytes().iter()).cloned().collect();
    let s2k_iterations = if s2k_count % pword.len() == 0 { s2k_count / pword.len() } else { (s2k_count / pword.len()) + 1 };

    let mut hash = crypto::SHA1::new();
    for _ in 0..s2k_iterations {
        hash.update(&pword);
    }
    let pword_hash = hash.unwrap();
    let aes_iv = &packet_data[e_mpi_end+13..e_mpi_end+29];
    let encrypted_data = &packet_data[e_mpi_end+29..];
    let mut aes = crypto::AES::new(&pword_hash);
    let decrypted_data = aes.cfb_decrypt(encrypted_data, aes_iv);
    let decrypted_sha_start = decrypted_data.len() - 20;
    let decrypted_sha = &decrypted_data[decrypted_sha_start..];
    let mut key_hash = crypto::SHA1::new();
    key_hash.update(&decrypted_data[..decrypted_sha_start]);
    let keydata_sha = key_hash.unwrap();
    if decrypted_sha != keydata_sha {
        return Err(PgpError::DecryptionChecksum);
    }

    let d_mpi_start = 2;
    let d_mpi_len = (((decrypted_data[0] as usize) << 8 | decrypted_data[1] as usize)+7) / 8;
    let d_mpi_end = d_mpi_start + d_mpi_len;
    let p_mpi_start = d_mpi_end+2;
    let p_mpi_len = (((decrypted_data[d_mpi_end] as usize) << 8 | decrypted_data[d_mpi_end+1] as usize)+7) / 8;
    let p_mpi_end = p_mpi_start + p_mpi_len;
    let q_mpi_start = p_mpi_end+2;
    let q_mpi_len = (((decrypted_data[p_mpi_end] as usize) << 8 | decrypted_data[p_mpi_end+1] as usize)+7) / 8;
    let q_mpi_end = q_mpi_start + q_mpi_len;
    let u_mpi_start = q_mpi_end+2;
    let u_mpi_len = (((decrypted_data[q_mpi_end] as usize) << 8 | decrypted_data[q_mpi_end+1] as usize)+7) / 8;
    let u_mpi_end = u_mpi_start + u_mpi_len;

    Ok(PrivateKey {n: packet_data[n_mpi_start..n_mpi_end].to_owned(),
                   e: packet_data[e_mpi_start..e_mpi_end].to_owned(),
                   d: decrypted_data[d_mpi_start..d_mpi_end].to_owned(),
                   p: decrypted_data[p_mpi_start..p_mpi_end].to_owned(),
                   q: decrypted_data[q_mpi_start..q_mpi_end].to_owned(),
                   u: decrypted_data[u_mpi_start..u_mpi_end].to_owned() })
}

pub fn read_armored_private_key(armored: &str, password: Option<&str>) -> PgpResult<PrivateKey> {
    let data = try!(read_armored(armored));
    read_private_key(&data, password)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crypto;

    pub static PUBDATA: &'static str ="-----BEGIN PGP PUBLIC KEY BLOCK-----
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

    pub static PRIVDATA: &'static str = "-----BEGIN PGP PRIVATE KEY BLOCK-----
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

    #[test]
    fn can_read_armored_public_key() {
        let expected_n = vec![166, 184, 160, 1, 253, 197, 7, 82, 163, 212, 128, 22, 97, 19, 164, 58, 113, 179, 43, 211, 78, 124, 38, 171, 24, 88, 15, 25, 101, 166, 166, 53, 101, 193, 8, 136, 96, 117, 81, 27, 66, 126, 252, 181, 76, 90, 51, 139, 74, 201, 30, 47, 208, 60, 237, 176, 117, 31, 177, 190, 186, 72, 139, 87, 126, 246, 98, 80, 40, 61, 149, 133, 42, 233, 215, 202, 34, 163, 127, 241, 171, 26, 10, 127, 180, 28, 191, 49, 198, 23, 142, 158, 10, 179, 3, 159, 114, 192, 95, 0, 154, 64, 226, 81, 99, 217, 100, 225, 181, 10, 142, 206, 90, 31, 62, 138, 2, 208, 187, 93, 47, 68, 117, 213, 249, 255, 148, 191];
        let expected_e = vec![1, 0, 1];

        let pubkey = read_armored_public_key(PUBDATA).unwrap();
        assert_eq!(pubkey.n.len(), 128);
        assert_eq!(pubkey.n, expected_n);
        assert_eq!(pubkey.e, expected_e);

        assert!(crypto::BIGNUM::from_bytes(&pubkey.e).is_prime());
    }

    #[test]
    fn can_read_armored_private_key() {
        let expected_n = vec![166, 184, 160, 1, 253, 197, 7, 82, 163, 212, 128, 22, 97, 19, 164, 58, 113, 179, 43, 211, 78, 124, 38, 171, 24, 88, 15, 25, 101, 166, 166, 53, 101, 193, 8, 136, 96, 117, 81, 27, 66, 126, 252, 181, 76, 90, 51, 139, 74, 201, 30, 47, 208, 60, 237, 176, 117, 31, 177, 190, 186, 72, 139, 87, 126, 246, 98, 80, 40, 61, 149, 133, 42, 233, 215, 202, 34, 163, 127, 241, 171, 26, 10, 127, 180, 28, 191, 49, 198, 23, 142, 158, 10, 179, 3, 159, 114, 192, 95, 0, 154, 64, 226, 81, 99, 217, 100, 225, 181, 10, 142, 206, 90, 31, 62, 138, 2, 208, 187, 93, 47, 68, 117, 213, 249, 255, 148, 191];
        let expected_e = vec![1, 0, 1];
        let expected_d = vec![14, 170, 192, 92, 220, 123, 232, 100, 131, 72, 47, 10, 136, 248, 198, 226, 99, 93, 77, 86, 54, 25, 226, 246, 251, 89, 199, 222, 70, 156, 142, 19, 181, 131, 113, 98, 58, 6, 40, 31, 251, 78, 27, 162, 65, 120, 207, 255, 9, 145, 190, 231, 154, 236, 185, 70, 100, 79, 104, 254, 43, 250, 52, 211, 213, 207, 54, 226, 66, 24, 45, 130, 148, 17, 34, 169, 143, 99, 90, 180, 243, 197, 134, 7, 28, 215, 116, 105, 164, 114, 188, 66, 116, 187, 231, 68, 134, 7, 98, 148, 171, 170, 30, 23, 86, 117, 71, 116, 205, 211, 85, 242, 82, 131, 231, 89, 191, 200, 235, 236, 82, 95, 158, 3, 116, 10, 61, 69];
        let expected_p = vec![195, 217, 45, 107, 236, 207, 2, 12, 208, 192, 85, 223, 99, 183, 151, 184, 73, 186, 177, 248, 102, 243, 204, 243, 84, 31, 186, 202, 54, 130, 133, 224, 87, 175, 141, 177, 252, 95, 77, 149, 236, 237, 197, 137, 81, 136, 118, 233, 27, 17, 169, 223, 104, 47, 161, 145, 148, 192, 151, 31, 43, 72, 252, 93];
        let expected_q = vec![217, 237, 73, 200, 174, 128, 175, 252, 176, 103, 83, 192, 155, 35, 35, 153, 40, 18, 155, 20, 197, 170, 3, 0, 90, 232, 25, 147, 23, 73, 130, 253, 59, 180, 139, 151, 233, 226, 122, 217, 14, 106, 61, 26, 31, 224, 174, 8, 179, 249, 206, 58, 21, 77, 248, 140, 177, 229, 63, 169, 175, 45, 227, 203];
        let expected_u = vec![180, 25, 41, 203, 183, 237, 80, 206, 246, 244, 84, 142, 239, 133, 17, 110, 159, 86, 128, 110, 13, 79, 51, 205, 127, 168, 203, 28, 187, 228, 186, 57, 171, 155, 172, 81, 52, 187, 240, 133, 197, 17, 139, 184, 150, 122, 49, 102, 194, 167, 34, 187, 129, 3, 72, 231, 161, 243, 193, 226, 167, 159, 156, 243];

        let privkey = read_armored_private_key(PRIVDATA, Some("password")).unwrap();
        assert_eq!(privkey.n, expected_n);
        assert_eq!(privkey.e, expected_e);
        assert_eq!(privkey.d, expected_d);
        assert_eq!(privkey.p, expected_p);
        assert_eq!(privkey.q, expected_q);
        assert_eq!(privkey.u, expected_u);

        assert!(crypto::BIGNUM::from_bytes(&privkey.e).is_prime());
        assert!(crypto::BIGNUM::from_bytes(&privkey.p).is_prime());
        assert!(crypto::BIGNUM::from_bytes(&privkey.q).is_prime());
    }
}
