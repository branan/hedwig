#![feature(convert)]

pub mod pgp;

pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>
}

pub struct PrivateKey {
    d: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    u: Vec<u8>
}