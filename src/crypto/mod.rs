mod ffi;

use std::ffi::CStr;
use std::fmt;
use std::mem;
use std::str;

#[derive(Debug)]
pub struct CryptoError {
    msg: String
}

impl CryptoError {
    fn new() -> CryptoError {
        unsafe {
            ffi::ERR_load_crypto_strings();
            let code = ffi::ERR_get_error();
            let c_buf = ffi::ERR_error_string(code, 0 as *mut u8);
            let c_str: &CStr = CStr::from_ptr(c_buf);
            let buf: &[u8] = c_str.to_bytes();
            let str = str::from_utf8(buf).unwrap();
            CryptoError { msg: str.to_owned() }
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "libcrypto: {}", self.msg)
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;

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

    pub fn finalize(mut self) -> [u8; 20] {
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
        assert!(keydata.len() == 16 || keydata.len() == 24 || keydata.len() == 32);
        let mut key: ffi::AES_KEY = Default::default();
        unsafe {
            ffi::AES_set_encrypt_key(keydata.as_ptr(), (keydata.len()*8) as ffi::c_int, &mut key);
            AES { key: key }
        }
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
    pub fn new(data: &[u8]) -> CryptoResult<BIGNUM> {
        unsafe {
            let bn = ffi::BN_new();
            if 0 == bn as usize {
                return Err(CryptoError::new());
            }
            let res = ffi::BN_bin2bn(data.as_ptr(), data.len() as ffi::c_int, bn);
            if 0 == res as usize {
                return Err(CryptoError::new());
            }
            Ok(BIGNUM { bn: bn })
        }
    }

    unsafe fn unwrap(self) -> *mut ffi::BIGNUM {
        let result = self.bn;
        mem::forget(self);
        result
    }
}

impl Drop for BIGNUM {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_clear_free(self.bn);
        }
    }
}

pub mod rand {
    pub fn bytes(count: i32) -> Vec<u8> {
        unsafe {
            let mut buffer: Vec<u8> = vec![0; count as usize];
            super::ffi::RAND_bytes(buffer.as_mut_ptr(), count);
            buffer
        }
    }
}

pub struct RSA {
    rsa: *mut ffi::RSA
}

impl RSA {
    pub fn new() -> CryptoResult<RSA> {
        unsafe {
            let rsa = ffi::RSA_new();
            if 0 == rsa as usize {
                return Err(CryptoError::new())
            }
            Ok(RSA { rsa: rsa })
        }
    }

    pub fn set_n(&mut self, data: BIGNUM) {
        unsafe {
            (*self.rsa).n = data.unwrap()
        }
    }

    pub fn set_e(&mut self, data: BIGNUM) {
        unsafe {
            (*self.rsa).e = data.unwrap()
        }
    }

    pub fn set_d(&mut self, data: BIGNUM) {
        unsafe {
            (*self.rsa).d = data.unwrap()
        }
    }

    pub fn set_p(&mut self, data: BIGNUM) {
        unsafe {
            (*self.rsa).p = data.unwrap()
        }
    }

    pub fn set_q(&mut self, data: BIGNUM) {
        unsafe {
            (*self.rsa).q = data.unwrap()
        }
    }

    pub fn public_encrypt(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let res = ffi::RSA_public_encrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if -1 == res {
                return Err(CryptoError::new())
            }
            Ok(result)
        }
    }
    pub fn public_decrypt(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let size = ffi::RSA_public_decrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if -1 == size {
                return Err(CryptoError::new())
            }
            result.truncate(size as usize);
            Ok(result)
        }
    }
    pub fn private_encrypt(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let res = ffi::RSA_private_encrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if -1 == res {
                return Err(CryptoError::new())
            }
            Ok(result)
        }
    }
    pub fn private_decrypt(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        unsafe {
            let mut result: Vec<u8> = vec![0; ffi::RSA_size(self.rsa) as usize];
            let size = ffi::RSA_private_decrypt(data.len() as ffi::c_int, data.as_ptr(), result.as_mut_ptr(), self.rsa, 1);
            if -1 == size {
                return Err(CryptoError::new())
            }
            result.truncate(size as usize);
            Ok(result)
        }
    }

    pub fn size(&self) -> usize {
        unsafe {
            ffi::RSA_size(self.rsa) as usize
        }
    }
}

impl Drop for RSA {
    fn drop(&mut self) {
        unsafe {
            ffi::RSA_free(self.rsa);
        }
    }
}
