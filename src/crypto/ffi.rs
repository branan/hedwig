extern crate libc;
pub use self::libc::{c_uint, c_int, c_void, size_t};

#[allow(dead_code)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct SHAstate {
    h0: c_uint,
    h1: c_uint,
    h2: c_uint,
    h3: c_uint,
    h4: c_uint,
    Nl: c_uint,
    Nh: c_uint,
    data: [c_uint; 16],
    num: c_uint
}

impl Default for SHAstate {
    fn default() -> SHAstate {
        SHAstate {
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            Nl: 0,
            Nh: 0,
            data: [0; 16],
            num: 0
        }
    }
}

#[allow(dead_code)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct AES_KEY {
    rd_key: [c_uint; 60],
    rounds: c_int
}

impl Default for AES_KEY {
    fn default() -> AES_KEY {
        AES_KEY {
            rd_key: [0; 60],
            rounds: 0
        }
    }
}

#[link(name = "crypto")]
extern {
    // SHA1
    pub fn SHA1_Init(c: *mut SHAstate) -> c_int;
    pub fn SHA1_Update(c: *mut SHAstate, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA1_Final(md: *mut u8, c: *mut SHAstate) -> c_int;

    // AES
    pub fn AES_set_encrypt_key(userKey: *const u8, bits: c_int, key: *mut AES_KEY) -> c_int;
    pub fn AES_cfb128_encrypt(int: *const u8, out: *mut u8, length: size_t, key: *const AES_KEY, ivec: *const u8, num: *mut c_int, enc: c_int) -> c_int;
}