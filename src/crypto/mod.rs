mod ffi;

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
        let mut num : ffi::c_int = 0;
        unsafe {
            ffi::AES_cfb128_encrypt(data.as_ptr(), decrypted.as_mut_ptr(), data.len() as ffi::size_t, &self.key, iv.as_ptr(), &mut num, 0);
        }
        decrypted
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