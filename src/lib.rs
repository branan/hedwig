#![feature(convert)]

pub mod pgp;

pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>
}
