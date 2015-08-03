pub mod pgp;
pub mod crypto;

use pgp::PgpKey;

use std::fmt;

#[derive(Debug)]
pub enum HedwigError {
    Signature,
    NotMyMessage,
    Crypto(crypto::CryptoError),
    Pgp(pgp::PgpError)
}

impl fmt::Display for HedwigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HedwigError::Crypto(ref err) => err.fmt(f),
            HedwigError::Pgp(ref err) => err.fmt(f),
            HedwigError::Signature => write!(f, "Signature validation failed"),
            HedwigError::NotMyMessage => write!(f, "Message not intended for this recipient")
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

pub struct Message<'a> {
    sender_fingerprint: Vec<u8>,
    aes_key: Vec<u8>,
    aes_iv: Vec<u8>,
    data: &'a [u8]
}

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
    let aes_key = crypto::rand::bytes(32);
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

pub fn receive_message<'a, 'b>(receiver: &'a pgp::PrivateKey, data: &'b [u8]) -> HedwigResult<Message<'b>> {
    let mut key = try!(pgp_private_to_ssl(receiver));

    let header_size = key.size();
    let header = try!(key.private_decrypt(&data[..header_size]));

    if header.len() != 88 {
        return Err(HedwigError::NotMyMessage);
    }

    let aes_key = &header[0..32];
    let aes_iv = &header[32..48];
    let recipient_fingerprint = &header[48..68];
    let sender_fingerprint = &header[68..88];

    if recipient_fingerprint != receiver.fingerprint() {
        Err(HedwigError::NotMyMessage)
    } else {
        Ok( Message { sender_fingerprint: sender_fingerprint.to_owned(),
                      aes_key: aes_key.to_owned(),
                      aes_iv: aes_iv.to_owned(),
                      data: &data[header_size..] })
    }
}

pub fn decrypt_message(sender: &pgp::PublicKey, msg: &Message) -> HedwigResult<Vec<u8>> {
    let mut key = try!(pgp_public_to_ssl(sender));
    let mut aes = crypto::AES::new(&msg.aes_key);
    let mut sha1 = crypto::SHA1::new();
    let sig_size = key.size();
    let signature = try!(key.public_decrypt(&msg.data[..sig_size]));
    let payload = &msg.data[sig_size..];
    sha1.update(&payload);
    let hash = sha1.finalize();
    if signature != hash {
        Err(HedwigError::Signature)
    } else {
        Ok(aes.cfb_decrypt(payload, &msg.aes_iv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::pgp::PgpKey;

    static MESSAGE: &'static str = "Hello, World!";

    #[test]
    fn can_roundtrip_message() {
        let pubkey = pgp::read_armored_packet(pgp::tests::PUBKEY, None)
            .unwrap().public_key().unwrap();
        let privkey = pgp::read_armored_packet(pgp::tests::PRIVKEY, Some("password"))
            .unwrap().private_key().unwrap();

        let encrypted_message = encrypt_message(&privkey, &pubkey, MESSAGE.as_bytes()).unwrap();

        let received_message = receive_message(&privkey, &encrypted_message).unwrap();
        assert_eq!(received_message.sender_fingerprint, privkey.fingerprint());

        let decrypted_message = decrypt_message(&pubkey, &received_message).unwrap();
        assert_eq!(decrypted_message, MESSAGE.as_bytes());
    }
}
