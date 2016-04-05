#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![deny(warnings)]
#![allow(unknown_lints)] // This lets us manage clippy lints without needing a cfg_attr check everywhere

extern crate gcrypt;

mod pgp;
mod crypto;

use std::fmt;
use pgp::PgpKey;

#[derive(Debug)]
pub enum HedwigError {
    KeyBlob,
    NoPrivate,
    NotMyMessage,
    Gcrypt(gcrypt::error::Error),
    Pgp(pgp::PgpError),
}

impl fmt::Display for HedwigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HedwigError::KeyBlob => write!(f, "Key file was of incorrect type"),
            HedwigError::NoPrivate => write!(f, "Private key was not yet initialized"),
            HedwigError::NotMyMessage => write!(f, "This message is for somebody else"),
            HedwigError::Pgp(ref err) => err.fmt(f),
            HedwigError::Gcrypt(ref err) => err.fmt(f),
        }
    }
}

impl From<gcrypt::error::Error> for HedwigError {
    fn from(err: gcrypt::error::Error) -> HedwigError {
       HedwigError::Gcrypt(err)
    }
}

impl From<pgp::PgpError> for HedwigError {
    fn from(err: pgp::PgpError) -> HedwigError {
        HedwigError::Pgp(err)
    }
}

pub type HedwigResult<T> = Result<T, HedwigError>;

pub struct Hedwig {
    token: gcrypt::Token,
    id: Option<pgp::PrivateKey>,
}

// TODO: remove this when we use the sender_fingerprint field outside
// of tests
#[cfg_attr(not(test), allow(dead_code))]
pub struct Message {
    sender_fingerprint: Vec<u8>,
    encrypted_body: Vec<u8>,
    key: gcrypt::Buffer,
    iv: gcrypt::Buffer,
}

impl Hedwig {
    pub fn new() -> Hedwig {
        let token = gcrypt::init(|mut gcry| {
            // TODO: Determine how much secure memory we actually need
            // I think this is insufficient for 8K keys, but I'm not sure :/
            gcry.enable_secmem(16384).unwrap();
        });
        Hedwig { token: token, id: None }
    }

    pub fn load_identity_from_blob(&mut self, armored_data: &str, password: Option<&[u8]>) -> HedwigResult<()> {
        let packet = try!(pgp::read_armored_packet(armored_data, password, self.token));
        match packet {
            pgp::Packet::PrivateKey(key) => self.id = Some(key),
            _ => return Err(HedwigError::KeyBlob)
        }
        Ok(())
    }

    pub fn encrypt_message(&self, recipient_key: &str, data: &[u8]) -> HedwigResult<Vec<u8>> {
        let recipient_key = match try!(pgp::read_armored_packet(recipient_key, None, self.token)) {
            pgp::Packet::PublicKey(key) => key,
            _ => return Err(HedwigError::KeyBlob)
        };
        let sender_key = try!(self.id.as_ref().ok_or(HedwigError::NoPrivate));

        let pubkey = try!(crypto::PubKey::from_pgp(&recipient_key, self.token));
        let privkey = try!(crypto::PrivKey::from_pgp(&sender_key, self.token));
        let recipient_fingerprint = try!(recipient_key.fingerprint(self.token));
        let sender_fingerprint = try!(sender_key.fingerprint(self.token));

        let key = try!(gcrypt::Buffer::random_secure(self.token,
                                                    16,
                                                    gcrypt::rand::STRONG_RANDOM));
        let iv = try!(gcrypt::Buffer::random_secure(self.token,
                                                    16,
                                                    gcrypt::rand::STRONG_RANDOM));
        let algo = gcrypt::cipher::CIPHER_AES;
        let mode = gcrypt::cipher::MODE_CFB;
        let mut cipher = try!(gcrypt::cipher::Cipher::new(self.token, algo, mode, gcrypt::cipher::Flags::empty()));
        try!(cipher.set_key(&key));
        try!(cipher.set_iv(&iv));
        let mut body = vec![0; data.len()];
        try!(cipher.encrypt(data, &mut body));

        let signature = try!(privkey.sign(data));

        let key_start = 0;
        let key_end = key_start + 16;
        let iv_start = key_end;
        let iv_end = iv_start + 16;
        let recip_start = iv_end;
        let recip_end = recip_start + recipient_fingerprint.len();
        let sender_start = recip_end;
        let sender_end = recip_end+sender_fingerprint.len();
        let header_len = sender_end - key_start;
        let mut header = try!(gcrypt::Buffer::new_secure(self.token, header_len));
        header[key_start..key_end].clone_from_slice(&key);
        header[iv_start..iv_end].clone_from_slice(&iv);
        header[recip_start..recip_end].clone_from_slice(&recipient_fingerprint);
        header[sender_start..sender_end].clone_from_slice(&sender_fingerprint);

        let encrypted_header = try!(pubkey.encrypt(&header));

        Ok(encrypted_header.iter()
           .chain(signature.iter())
           .chain(body.iter())
           .cloned().collect())
    }

    pub fn receive_message(&self, data: &[u8]) -> HedwigResult<Message> {
        let recipient_key = try!(self.id.as_ref().ok_or(HedwigError::NoPrivate));
        let recipient_fingerprint = try!(recipient_key.fingerprint(self.token));
        let privkey = try!(crypto::PrivKey::from_pgp(recipient_key, self.token));

        // TODO: This doesn't decrypt to secure memory
        let encrypted_header = &data[0..privkey.blocklen()];
        let header = try!(privkey.decrypt(&encrypted_header));

        let key_start = 0;
        let key_end = key_start + 16;
        let iv_start = key_end;
        let iv_end = iv_start + 16;
        let recip_start = iv_end;
        let recip_end = recip_start + recipient_fingerprint.len();
        let sender_start = recip_end;
        let sender_end = header.len();

        if &header[recip_start..recip_end] != &recipient_fingerprint[..] {
            return Err(HedwigError::NotMyMessage);
        }

        let sender_fingerprint = &header[sender_start..sender_end];
        let mut key = try!(gcrypt::Buffer::new_secure(self.token, 16));
        let mut iv = try!(gcrypt::Buffer::new_secure(self.token, 16));
        key.clone_from_slice(&header[key_start..key_end]);
        iv.clone_from_slice(&header[iv_start..iv_end]);
        Ok(Message{sender_fingerprint: sender_fingerprint.to_owned(),
                   encrypted_body: data[privkey.blocklen()..].to_owned(),
                   key: key,
                   iv: iv})
    }

    pub fn decrypt_message(&self, sender_key: &str, message: &Message) -> HedwigResult<Vec<u8>> {
        let sender_key = match try!(pgp::read_armored_packet(sender_key, None, self.token)) {
            pgp::Packet::PublicKey(key) => try!(crypto::PubKey::from_pgp(&key, self.token)),
            _ => return Err(HedwigError::KeyBlob)
        };

        let signature_len = sender_key.blocklen();
        let signature = &message.encrypted_body[0..signature_len];

        let algo = gcrypt::cipher::CIPHER_AES;
        let mode = gcrypt::cipher::MODE_CFB;
        let mut cipher = try!(gcrypt::cipher::Cipher::new(self.token, algo, mode, gcrypt::cipher::Flags::empty()));
        try!(cipher.set_key(&message.key));
        try!(cipher.set_iv(&message.iv));
        let mut body = vec![0; message.encrypted_body.len() - signature_len];
        try!(cipher.decrypt(&message.encrypted_body[signature_len..], &mut body));

        try!(sender_key.verify(signature, &body));
        Ok(body)
    }
}

impl Default for Hedwig {
    fn default() -> Hedwig {
        Hedwig::new()
    }
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


    pub const EXPECTED_N: [u8; 128] = [166, 184, 160, 1, 253, 197, 7, 82, 163, 212, 128, 22, 97, 19, 164, 58, 113, 179, 43, 211, 78, 124, 38, 171, 24, 88, 15, 25, 101, 166, 166, 53, 101, 193, 8, 136, 96, 117, 81, 27, 66, 126, 252, 181, 76, 90, 51, 139, 74, 201, 30, 47, 208, 60, 237, 176, 117, 31, 177, 190, 186, 72, 139, 87, 126, 246, 98, 80, 40, 61, 149, 133, 42, 233, 215, 202, 34, 163, 127, 241, 171, 26, 10, 127, 180, 28, 191, 49, 198, 23, 142, 158, 10, 179, 3, 159, 114, 192, 95, 0, 154, 64, 226, 81, 99, 217, 100, 225, 181, 10, 142, 206, 90, 31, 62, 138, 2, 208, 187, 93, 47, 68, 117, 213, 249, 255, 148, 191];
    pub const EXPECTED_E: [u8; 3] = [1, 0, 1];
    pub const EXPECTED_D: [u8; 128] = [14, 170, 192, 92, 220, 123, 232, 100, 131, 72, 47, 10, 136, 248, 198, 226, 99, 93, 77, 86, 54, 25, 226, 246, 251, 89, 199, 222, 70, 156, 142, 19, 181, 131, 113, 98, 58 , 6, 40, 31, 251, 78, 27, 162, 65, 120, 207, 255, 9, 145, 190, 231, 154, 236, 185, 70, 100, 79, 104, 254, 43, 250, 52, 211, 213, 207, 54, 226, 66, 24, 45, 130, 148, 17, 34, 169, 143, 99, 90, 180, 243, 197, 134, 7, 28, 215, 116, 105, 164, 114, 188, 66, 116, 187, 231, 68, 134, 7, 98, 148, 171, 170, 30, 23, 86, 117, 71, 116, 205, 211, 85, 242, 82, 131, 231, 89, 191, 200, 235, 236, 82, 95, 158, 3, 116, 10, 61, 69];
    pub const EXPECTED_P: [u8; 64] = [195, 217, 45, 107, 236, 207, 2, 12, 208, 192, 85, 223, 99, 183, 151, 184, 73, 186, 177, 248, 102, 243, 204, 243, 84, 31, 186, 202, 54, 130, 133, 224, 87, 175, 141, 177, 252, 95, 77, 149, 236, 237, 197, 137, 81, 136, 118, 233, 27, 17, 169, 223, 104, 47, 161, 145, 148, 192, 151, 31, 43, 72, 252, 93];
    pub const EXPECTED_Q: [u8; 64] = [217, 237, 73, 200, 174, 128, 175, 252, 176, 103, 83, 192, 155, 35, 35, 153, 40, 18, 155, 20, 197, 170, 3, 0, 90, 232, 25, 147, 23, 73, 130, 253, 59, 180, 139, 151, 233, 226, 122, 217, 14, 106, 61, 26, 31, 224, 174, 8, 179, 249, 206, 58, 21, 77, 248, 140, 177, 229, 63, 169, 175, 45, 227, 203];
    pub const EXPECTED_U: [u8; 64] = [180, 25, 41, 203, 183, 237, 80, 206, 246, 244, 84, 142, 239, 133, 17, 110, 159, 86, 128, 110, 13, 79, 51, 205, 127, 168, 203, 28, 187, 228, 186, 57, 171, 155, 172, 81, 52, 187, 240, 133, 197, 17, 139, 184, 150, 122, 49, 102, 194, 167, 34, 187, 129, 3, 72, 231, 161, 243, 193, 226, 167, 159, 156, 243];
    pub const EXPECTED_FINGERPRINT: [u8; 20] = [207, 88, 186, 9, 9, 128, 178, 190, 109, 45, 4, 61, 128, 224, 190, 186, 69, 94, 210, 211];

    static MESSAGE: &'static str = "Hello, World!";

    #[test]
    fn can_initialize() {
        Hedwig::new();
    }

    #[test]
    fn can_load_identity() {
        let mut instance = Hedwig::new();
        instance.load_identity_from_blob(PRIVKEY, Some(b"password")).unwrap();
    }

    #[test]
    fn can_roundtrip_message() {
        let mut instance = Hedwig::new();
        instance.load_identity_from_blob(PRIVKEY, Some(b"password")).unwrap();
        let encrypted_message = instance.encrypt_message(PUBKEY, MESSAGE.as_bytes());

        let message = match encrypted_message {
            Err(e) => {
                println!("Failed to encrypt message: {}", e);
                panic!();
            },
            Ok(v) => v,
        };

        let received_message = instance.receive_message(&message).unwrap();
        assert_eq!(received_message.sender_fingerprint, EXPECTED_FINGERPRINT);

        let decrypted_message = instance.decrypt_message(PUBKEY, &received_message).unwrap();
        assert_eq!(decrypted_message, MESSAGE.as_bytes());
    }

}
