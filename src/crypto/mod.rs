mod ffi;

use std::ffi::CStr;
use std::str;

pub struct SHA1 {
    state: ffi::SHAstate,
}

impl SHA1 {
    pub fn new() -> SHA1 {
        let mut state: ffi::SHAstate = Default::default();
        unsafe {
            ffi::SHA1_Init(&mut state);
        }
        SHA1 { state: state }
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            ffi::SHA1_Update(&mut self.state, data.as_ptr() as *mut ffi::c_void, data.len() as ffi::size_t);
        }
    }

    pub fn unwrap(mut self) -> [u8; 20] {
        let mut result: [u8; 20] = [0; 20];
        unsafe {
            ffi::SHA1_Final(result.as_mut_ptr(), &mut self.state);
        }
        result
    }
}

pub struct AES {
    key: ffi::AES_KEY
}

impl AES {
    pub fn new(keydata: &[u8]) -> AES {
        let mut key: ffi::AES_KEY = Default::default();
        unsafe {
            ffi::AES_set_encrypt_key(keydata[0..16].as_ptr(), 128, &mut key);
        }
        AES { key: key }
    }

    pub fn cfb_decrypt(&mut self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut decrypted : Vec<u8> = vec![0; data.len()];
        let mut iv_internal : Vec<u8> = iv.to_owned();
        let mut num : ffi::c_int = 0;
        unsafe {
            ffi::AES_cfb128_encrypt(data.as_ptr(), decrypted.as_mut_ptr(), data.len() as ffi::size_t, &self.key, iv_internal.as_mut_ptr(), &mut num, 0);
        }
        decrypted
    }

    pub fn cfb_encrypt(&mut self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut encrypted : Vec<u8> = vec![0; data.len()];
        let mut iv_internal : Vec<u8> = iv.to_owned();
        let mut num : ffi::c_int = 0;
        unsafe {
            ffi::AES_cfb128_encrypt(data.as_ptr(), encrypted.as_mut_ptr(), data.len() as ffi::size_t, &self.key, iv_internal.as_mut_ptr(), &mut num, 1);
        }
        encrypted
    }
}

pub struct BIGNUM {
    // bignums are alwas heap-allocated, so we can just call it a void*
    bn: *mut ffi::BIGNUM
}

impl BIGNUM {
    pub fn from_bytes(data: &[u8]) -> BIGNUM {
        unsafe {
            let bn = ffi::BN_new();
            ffi::BN_bin2bn(data.as_ptr(), data.len() as ffi::c_int, bn);
            BIGNUM { bn: bn }
        }
    }

    pub fn is_prime(&self) -> bool {
        unsafe {
            let ctx = ffi::BN_CTX_new();
            let result = ffi::BN_is_prime_ex(self.bn, 0, ctx, 0 as *const ffi::c_void);
            ffi::BN_CTX_free(ctx);
            if result == 1 { true } else { false }
        }
    }
}

impl Drop for BIGNUM {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_clear_free(self.bn);
        }
    }
}

pub struct RAND;

impl RAND {
    pub fn bytes(count: i32) -> Vec<u8> {
        unsafe {
            let mut buffer: Vec<u8> = vec![0; count as usize];
            ffi::RAND_bytes(buffer.as_mut_ptr(), count);
            buffer
        }
    }
}

pub struct RSA {
    rsa: *mut ffi::RSA
}

impl RSA {
    pub fn from_public(key: &super::PublicKey) -> RSA {
        unsafe {
            let rsa = ffi::RSA_new();
            (*rsa).n = ffi::BN_new();
            (*rsa).e = ffi::BN_new();
            ffi::BN_bin2bn(key.n.as_ptr(), key.n.len() as ffi::c_int, (*rsa).n);
            ffi::BN_bin2bn(key.e.as_ptr(), key.e.len() as ffi::c_int, (*rsa).e);

            RSA { rsa: rsa }
        }
    }

    pub fn from_private(key: &super::PrivateKey) -> RSA {
        unsafe {
            let rsa = ffi::RSA_new();
            (*rsa).n = ffi::BN_new();
            (*rsa).e = ffi::BN_new();
            (*rsa).d = ffi::BN_new();
            (*rsa).p = ffi::BN_new();
            (*rsa).q = ffi::BN_new();

            ffi::BN_bin2bn(key.n.as_ptr(), key.n.len() as ffi::c_int, (*rsa).n);
            ffi::BN_bin2bn(key.e.as_ptr(), key.e.len() as ffi::c_int, (*rsa).e);
            ffi::BN_bin2bn(key.d.as_ptr(), key.d.len() as ffi::c_int, (*rsa).d);
            ffi::BN_bin2bn(key.p.as_ptr(), key.p.len() as ffi::c_int, (*rsa).p);
            ffi::BN_bin2bn(key.q.as_ptr(), key.q.len() as ffi::c_int, (*rsa).q);

            let check_result = ffi::RSA_check_key(rsa);
            RSA { rsa: rsa }
        }
    }

    pub fn public_encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let err = ffi::RSA_public_encrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if err < 0 {
                println!("public_encrypt: {}", error_str());
            }
            result
        }
    }
    pub fn public_decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let size = ffi::RSA_public_decrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if size < 0 {
                println!("public_decrypt: {}", error_str());
            }
            result.truncate(size as usize);
            result
        }
    }
    pub fn private_encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let err = ffi::RSA_private_encrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if err < 0 {
                println!("private_encrypt: {}", error_str());
            }
            result
        }
    }
    pub fn private_decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let size = ffi::RSA_private_decrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if size < 0 {
                println!("private_decrypt: {}", error_str());
            }
            result.truncate(size as usize);
            result
        }
    }

    pub fn size(&self) -> usize {
        unsafe {
            ffi::RSA_size(self.rsa) as usize
        }
    }
}

fn error_str() -> String {
    unsafe {
        ffi::ERR_load_crypto_strings();
        let code = ffi::ERR_get_error();
        let c_buf = ffi::ERR_error_string(code, 0 as *mut u8);
        let c_str: &CStr = CStr::from_ptr(c_buf);
        let buf: &[u8] = c_str.to_bytes();
        let str = str::from_utf8(buf).unwrap();
        str.to_owned()
    }
}