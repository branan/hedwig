pub mod pgp;
pub mod crypto;

use pgp::PgpKey;

use std::fmt;

#[derive(Debug)]
pub enum HedwigError {
    Signature,
    Crypto(crypto::CryptoError),
    Pgp(pgp::PgpError)
}

impl fmt::Display for HedwigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HedwigError::Crypto(ref err) => err.fmt(f),
            HedwigError::Pgp(ref err) => err.fmt(f),
            HedwigError::Signature => write!(f, "Signature validation failed")
        }
    }
}

impl From<crypto::CryptoError> for HedwigError {
    fn from(err: crypto::CryptoError) -> HedwigError {
        HedwigError::Crypto(err)
    }
}

impl From<pgp::PgpError> for HedwigError {
    fn from(err: pgp::PgpError) -> HedwigError {
        HedwigError::Pgp(err)
    }
}

pub type HedwigResult<T> = Result<T, HedwigError>;

fn pgp_public_to_ssl(pgp: &pgp::PublicKey) -> crypto::CryptoResult<crypto::RSA> {
    let mut key = try!(crypto::RSA::new());
    key.set_n(try!(crypto::BIGNUM::new(&pgp.n)));
    key.set_e(try!(crypto::BIGNUM::new(&pgp.e)));
    Ok(key)
}

fn pgp_private_to_ssl(pgp: &pgp::PrivateKey) -> crypto::CryptoResult<crypto::RSA> {
    let mut key = try!(pgp_public_to_ssl(&pgp.public));
    key.set_d(try!(crypto::BIGNUM::new(&pgp.d)));
    key.set_p(try!(crypto::BIGNUM::new(&pgp.p)));
    key.set_q(try!(crypto::BIGNUM::new(&pgp.q)));
    Ok(key)
}

pub fn encrypt_message(sender: &pgp::PrivateKey, receiver: &pgp::PublicKey, data: &[u8]) -> HedwigResult<Vec<u8>> {
    let aes_key = crypto::rand::bytes(16);
    let mut aes = crypto::AES::new(&aes_key);
    let iv = crypto::rand::bytes(16);
    let payload = aes.cfb_encrypt(data, &iv);

    let mut pub_key = try!(pgp_public_to_ssl(receiver));
    let mut priv_key = try!(pgp_private_to_ssl(sender));

    let mut sha1 = crypto::SHA1::new();
    sha1.update(&payload);
    let payload_hash = sha1.finalize();

    let signature = try!(priv_key.private_encrypt(&payload_hash));

    let header: Vec<u8> = aes_key.iter()
        .chain(iv.iter())
        .chain(receiver.fingerprint().iter())
        .chain(sender.fingerprint().iter())
        .cloned().collect();
    let encrypted_header = try!(pub_key.public_encrypt(&header));

    Ok(encrypted_header.iter()
       .chain(signature.iter())
       .chain(payload.iter())
       .cloned().collect())
}

pub fn decrypt_message(receiver: &pgp::PrivateKey, sender: &pgp::PublicKey, data: &[u8]) -> HedwigResult<Vec<u8>> {
    let mut priv_key = try!(pgp_private_to_ssl(receiver));
    let mut pub_key = try!(pgp_public_to_ssl(sender));

    let priv_size = priv_key.size();
    let pub_size = pub_key.size();
    let header = try!(priv_key.private_decrypt(&data[..priv_size]));
    let signature = try!(pub_key.public_decrypt(&data[priv_size..priv_size+pub_size]));
    let payload = &data[priv_size+pub_size..];
    let mut sha1 = crypto::SHA1::new();
    sha1.update(&payload);
    let payload_hash = sha1.finalize();
    if signature != payload_hash {
        return Err(HedwigError::Signature)
    }
    let mut aes = crypto::AES::new(&header[0..16]);
    Ok(aes.cfb_decrypt(payload, &header[16..32]))
}

#[cfg(test)]
mod tests {
    use super::*;

    static MESSAGE: &'static str = "Hello, World!";

    #[test]
    fn can_roundtrip_message() {
        let pubkey = pgp::read_armored_packet(pgp::tests::PUBKEY, None)
            .unwrap().public_key().unwrap();
        let privkey = pgp::read_armored_packet(pgp::tests::PRIVKEY, Some("password"))
            .unwrap().private_key().unwrap();

        let encrypted_message = encrypt_message(&privkey, &pubkey, MESSAGE.as_bytes()).unwrap();
        let decrypted_message = decrypt_message(&privkey, &pubkey, &encrypted_message).unwrap();

        assert_eq!(decrypted_message, MESSAGE.as_bytes());
    }
}
