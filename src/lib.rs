#![feature(convert)]

pub mod pgp;
pub mod crypto;

pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>
}

pub struct PrivateKey {
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    u: Vec<u8>
}