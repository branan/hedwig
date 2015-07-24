extern crate libc;
pub use self::libc::{c_char, c_uint, c_int, c_long, c_ulong, c_void, size_t};

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

#[repr(C)]
pub struct BIGNUM;
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct RSA_METHOD;
#[repr(C)]
pub struct ENGINE;

#[allow(non_camel_case_types)]
#[repr(C)]
struct CRYPTO_EX_DATA {
    sk: *mut c_void,
    dummy: c_int
}

#[repr(C)]
pub struct RSA {
    pad: c_int,
    version: c_long,
    meth: *const RSA_METHOD,
    engine: *mut ENGINE,
    pub n: *mut BIGNUM,
    pub e: *mut BIGNUM,
    pub d: *mut BIGNUM,
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub dmp1: *mut BIGNUM,
    pub dmq1: *mut BIGNUM,
    pub iqmp: *mut BIGNUM,
    ex_data: CRYPTO_EX_DATA,
    references: c_int,
    flags: c_int,
    _method_mod_n: *mut c_void,
    _method_mod_p: *mut c_void,
    _method_mod_q: *mut c_void,
    bignum_data: *mut u8,
    blinding: *mut c_void,
    mt_blinding: *mut c_void
}

#[link(name = "crypto")]
extern {
    // ERR
    pub fn ERR_load_crypto_strings();
    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_error_string(e: c_ulong, buf: *mut u8) -> *const c_char;

    // SHA1
    pub fn SHA1_Init(c: *mut SHAstate) -> c_int;
    pub fn SHA1_Update(c: *mut SHAstate, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA1_Final(md: *mut u8, c: *mut SHAstate) -> c_int;

    // AES
    pub fn AES_set_encrypt_key(userKey: *const u8, bits: c_int, key: *mut AES_KEY) -> c_int;
    pub fn AES_cfb128_encrypt(int: *const u8, out: *mut u8, length: size_t, key: *const AES_KEY, ivec: *mut u8, num: *mut c_int, enc: c_int) -> c_int;

    // BIGNUM
    pub fn BN_new() -> *mut BIGNUM;
    pub fn BN_clear_free(a: *mut BIGNUM);
    pub fn BN_bin2bn(s: *const u8, len: c_int, to: *mut BIGNUM) -> *mut BIGNUM;

    // RAND
    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;

    // RSA
    pub fn RSA_new() -> *mut RSA;
    pub fn RSA_free(r: *mut RSA);
    pub fn RSA_size(r: *const RSA) -> c_int;
    pub fn RSA_public_encrypt(flen: c_int, from: *const u8, to: *mut u8, rsa: *mut RSA, padding: c_int) -> c_int;
    pub fn RSA_public_decrypt(flen: c_int, from: *const u8, to: *mut u8, rsa: *mut RSA, padding: c_int) -> c_int;
    pub fn RSA_private_encrypt(flen: c_int, from: *const u8, to: *mut u8, rsa: *mut RSA, padding: c_int) -> c_int;
    pub fn RSA_private_decrypt(flen: c_int, from: *const u8, to: *mut u8, rsa: *mut RSA, padding: c_int) -> c_int;
}
