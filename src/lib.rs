pub mod pgp;
pub mod crypto;

use pgp::PgpKey;

fn pgp_public_to_ssl(pgp: &pgp::PublicKey) -> crypto::RSA {
    let mut key = crypto::RSA::new();
    key.set_n(crypto::BIGNUM::new(&pgp.n));
    key.set_e(crypto::BIGNUM::new(&pgp.e));
    key
}

fn pgp_private_to_ssl(pgp: &pgp::PrivateKey) -> crypto::RSA {
    let mut key = pgp_public_to_ssl(&pgp.public);
    key.set_d(crypto::BIGNUM::new(&pgp.d));
    key.set_p(crypto::BIGNUM::new(&pgp.p));
    key.set_q(crypto::BIGNUM::new(&pgp.q));
    key
}

pub fn encrypt_message(sender: &pgp::PrivateKey, receiver: &pgp::PublicKey, data: &[u8]) -> Vec<u8> {
    let aes_key = crypto::rand::bytes(16);
    let mut aes = crypto::AES::new(&aes_key);
    let iv = crypto::rand::bytes(16);
    let payload = aes.cfb_encrypt(data, &iv);

    let mut pub_key = pgp_public_to_ssl(receiver);
    let mut priv_key = pgp_private_to_ssl(sender);

    let mut sha1 = crypto::SHA1::new();
    sha1.update(&payload);
    let payload_hash = sha1.unwrap();

    let signature = priv_key.private_encrypt(&payload_hash);

    let header: Vec<u8> = aes_key.iter()
        .chain(iv.iter())
        .chain(receiver.fingerprint().iter())
        .chain(sender.fingerprint().iter())
        .cloned().collect();
    let encrypted_header = pub_key.public_encrypt(&header);

    encrypted_header.iter().chain(signature.iter()).chain(payload.iter()).cloned().collect()
}

pub fn decrypt_message(receiver: &pgp::PrivateKey, sender: &pgp::PublicKey, data: &[u8]) -> Vec<u8> {
    let mut priv_key = pgp_private_to_ssl(receiver);
    let mut pub_key = pgp_public_to_ssl(sender);

    let priv_size = priv_key.size();
    let pub_size = pub_key.size();
    let header = priv_key.private_decrypt(&data[..priv_size]);
    let signature = pub_key.public_decrypt(&data[priv_size..priv_size+pub_size]);
    let payload = &data[priv_size+pub_size..];
    let mut sha1 = crypto::SHA1::new();
    sha1.update(&payload);
    let payload_hash = sha1.unwrap();
    let mut aes = crypto::AES::new(&header[0..16]);
    aes.cfb_decrypt(payload, &header[16..32])
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

        let encrypted_message = encrypt_message(&privkey, &pubkey, MESSAGE.as_bytes());
        let decrypted_message = decrypt_message(&privkey, &pubkey, &encrypted_message);

        assert_eq!(decrypted_message, MESSAGE.as_bytes());
    }
}
