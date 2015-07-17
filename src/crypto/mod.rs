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