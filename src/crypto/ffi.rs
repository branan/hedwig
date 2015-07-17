extern crate libc;
pub use self::libc::{c_uint, c_int, c_void, size_t};

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

#[link(name = "crypto")]
extern {
    pub fn SHA1_Init(c: *mut SHAstate) -> c_int;
    pub fn SHA1_Update(c: *mut SHAstate, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA1_Final(md: *mut u8, c: *mut SHAstate) -> c_int;
}