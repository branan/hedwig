mod ffi;

pub struct SHA1 {
    state: ffi::SHAstate,
    result: [u8; 20],
}

impl SHA1 {
    pub fn new() -> SHA1 {
        let mut state: ffi::SHAstate = Default::default();
        unsafe {
            ffi::SHA1_Init(&mut state);
        }
        SHA1 { state: state, result: [0; 20] }
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            ffi::SHA1_Update(&mut self.state, data.as_ptr() as *mut ffi::c_void, data.len() as ffi::size_t);
        }
    }

    pub fn finish(&mut self) {
        unsafe {
            ffi::SHA1_Final(self.result.as_mut_ptr(), &mut self.state);
        }
    }

    pub fn get_result(&self) -> &[u8] {
        &self.result
    }
}