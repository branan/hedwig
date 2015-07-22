pub mod pgp;
pub mod crypto;

pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

pub struct PrivateKey {
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    u: Vec<u8>,
}

trait Key {
    fn n(&self) -> &[u8];
    fn e(&self) -> &[u8];
}

impl Key for PrivateKey {
    fn n(&self) -> &[u8] {
        &self.n
    }

    fn e(&self) -> &[u8] {
        &self.e
    }
}

impl Key for PublicKey {
    fn n(&self) -> &[u8] {
        &self.n
    }

    fn e(&self) -> &[u8] {
        &self.e
    }
}

pub fn encrypt_message(sender: &PrivateKey, receiver: &PublicKey, data: &[u8]) -> Vec<u8> {
    let aes_key = crypto::RAND::bytes(16);
    let mut aes = crypto::AES::new(&aes_key);
    let iv = crypto::RAND::bytes(16);
    let payload = aes.cfb_encrypt(data, &iv);

    let mut pub_key = crypto::RSA::from_public(receiver);
    let mut priv_key = crypto::RSA::from_private(sender);

    let mut sha1 = crypto::SHA1::new();
    sha1.update(&payload);
    let payload_hash = sha1.unwrap();

    let signature = priv_key.private_encrypt(&payload_hash);

    let len = payload.len() as u32;
    let len_buf = vec![(len >> 24) as u8 & 0xff, (len >> 16) as u8 & 0xff, (len >> 8 ) as u8 & 0xff, len as u8 & 0xff];

    let header: Vec<u8> = aes_key.iter().chain(iv.iter()).chain(len_buf.iter()).cloned().collect();
    let encrypted_header = pub_key.public_encrypt(&header);

    encrypted_header.iter().chain(signature.iter()).chain(payload.iter()).cloned().collect()
}

pub fn decrypt_message(reciever: &PrivateKey, sender: &PublicKey, data: &[u8]) -> Vec<u8> {
    let mut priv_key = crypto::RSA::from_private(reciever);
    let mut pub_key = crypto::RSA::from_public(sender);

    let priv_size = priv_key.size();
    let pub_size = pub_key.size();
    let header = priv_key.private_decrypt(&data[..priv_size]);
    let signature = &data[priv_size..priv_size+pub_size];
    let payload = &data[priv_size+pub_size..];
    let mut aes = crypto::AES::new(&header[0..16]);
    aes.cfb_decrypt(payload, &header[16..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    static MESSAGE: &'static str = "Hello, World!";

    #[test]
    fn can_roundtrip_message() {
        let pubkey = pgp::read_armored_public_key(pgp::tests::PUBDATA).unwrap();
        let privkey = pgp::read_armored_private_key(pgp::tests::PRIVDATA, Some("password")).unwrap();

        let encrypted_message = encrypt_message(&privkey, &pubkey, MESSAGE.as_bytes());
        let decrypted_message = decrypt_message(&privkey, &pubkey, &encrypted_message);

        assert_eq!(decrypted_message, MESSAGE.as_bytes());
    }
}
