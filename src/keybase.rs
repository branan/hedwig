use std::borrow::Borrow;

pub struct User {
    public_key: String
}

impl User {
    pub fn public_key(&self) -> &str {
        self.public_key.borrow()
    }
}

pub fn fetch_user(name: String) -> User {
   User{ public_key: "".to_string() }
}