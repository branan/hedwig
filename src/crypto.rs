use gcrypt;
use gcrypt::mpi;
use gcrypt::sexp;
use gcrypt::digest;

#[cfg(feature = "keybase")]
use gcrypt::mac;

#[cfg(feature = "keybase")]
use gcrypt::kdf;

use pgp;

pub type Token = gcrypt::Token;
pub type Result<T> = gcrypt::error::Result<T>;

pub struct PubKey {
    key: sexp::SExpression,
    token: Token,
}

pub struct PrivKey {
    key: sexp::SExpression,
    token: Token,
}

impl PubKey {
    pub fn from_pgp(key: &pgp::PublicKey, token: Token) -> Result<PubKey> {
        let n = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.n));
        let e = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.e));
        let template = try!(sexp::Template::new("(public-key (rsa (n %m) (e %m)))"));
        let mut builder = sexp::Builder::from(&template);
        builder
            .add_mpi(&n)
            .add_mpi(&e);
        let sexp = try!(builder.build(token));
        Ok(PubKey{key: sexp, token: token})
    }

    pub fn verify(&self, signature: &[u8], data: &[u8]) -> Result<()> {
        let sig = try!(mpi::Integer::from_bytes(self.token, mpi::integer::Format::Unsigned, signature));
        let sig_template = try!(sexp::Template::new("(sig-val (rsa (s %m)))"));
        let mut sig_builder = sexp::Builder::from(&sig_template);
        sig_builder.add_mpi(&sig);
        let sig_sexp = try!(sig_builder.build(self.token));

        let hash = try!(sha1(data, self.token));
        let template = try!(sexp::Template::new("(data (flags pkcs1) (hash sha1 %b))"));
        let mut builder = sexp::Builder::from(&template);
        builder.add_bytes(&hash);
        let data_sexp = try!(builder.build(self.token));

        self.key.verify(&sig_sexp, &data_sexp)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<gcrypt::Buffer> {
        let template = try!(sexp::Template::new("(data (flags pkcs1) (value %b))"));
        let mut builder = sexp::Builder::from(&template);
        builder.add_bytes(data);
        let data_sexp = try!(builder.build(self.token));
        let result = try!(self.key.encrypt(&data_sexp));
        result.find_token("a").unwrap()
            .get_integer(1, mpi::integer::Format::Unsigned).unwrap()
            .to_bytes(mpi::integer::Format::Unsigned)
    }

    pub fn blocklen(&self) -> usize {
        let remainder = self.key.num_bits().unwrap_or(0) % 8;
        let keybytes = self.key.num_bits().unwrap_or(0) / 8;
        if remainder == 0 { keybytes } else { keybytes + 1 }
    }
}

impl PrivKey {
    #[allow(many_single_char_names)]
    pub fn from_pgp(key: &pgp::PrivateKey, token: Token) -> Result<PrivKey> {
        // TODO: I don't think this is putting the MPI into secure memory
        let n = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.public.n));
        let e = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.public.e));
        let d = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.d));
        let p = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.p));
        let q = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.q));
        let u = try!(mpi::Integer::from_bytes(token, mpi::integer::Format::Unsigned, &key.u));
        let template = try!(sexp::Template::new("(private-key (rsa (n %m) (e %m) (d %m) (p %m) (q %m) (u %m)))"));
        let mut builder = sexp::Builder::from(&template);
        builder
            .add_mpi(&n)
            .add_mpi(&e)
            .add_mpi(&d)
            .add_mpi(&p)
            .add_mpi(&q)
            .add_mpi(&u);
        let sexp = try!(builder.build(token));
        Ok(PrivKey{key: sexp, token: token})
    }

    pub fn sign(&self, data: &[u8]) -> Result<gcrypt::Buffer> {
        let hash = try!(sha1(data, self.token));
        try!(self.key.test_key());
        let template = try!(sexp::Template::new("(data (flags pkcs1) (hash sha1 %b))"));
        let mut builder = sexp::Builder::from(&template);
        builder.add_bytes(&hash);
        let data_sexp = try!(builder.build(self.token));
        let result = try!(self.key.sign(&data_sexp));
        result.find_token("s").unwrap()
            .get_integer(1, mpi::integer::Format::Unsigned).unwrap()
            .to_bytes(mpi::integer::Format::Unsigned)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let a = try!(mpi::Integer::from_bytes(self.token, mpi::integer::Format::Unsigned, data));
        let template = try!(sexp::Template::new("(enc-val (flags pkcs1) (rsa (a %m)))"));
        let mut builder = sexp::Builder::from(&template);
        builder.add_mpi(&a);
        let data_sexp = try!(builder.build(self.token));
        let result = try!(self.key.decrypt(&data_sexp));
        Ok(result.find_token("value").unwrap().get_bytes(1).unwrap().to_owned())
    }

    pub fn blocklen(&self) -> usize {
        let remainder = self.key.num_bits().unwrap_or(0) % 8;
        let keybytes = self.key.num_bits().unwrap_or(0) / 8;
        if remainder == 0 { keybytes } else { keybytes + 1 }
    }
}

pub fn sha1(bytes: &[u8], token: Token) -> Result<Vec<u8>> {
    let algo = digest::MD_SHA1;
    let mut sha = try!(digest::MessageDigest::new(token, algo, gcrypt::digest::Flags::empty()));
    sha.write(bytes);
    Ok(sha.get_digest(algo).unwrap().to_owned())
}

#[cfg(feature = "keybase")]
pub fn scrypt(password: &str, salt: &[u8], out: &mut [u8], token: Token) -> Result<()> {
    try!(kdf::scrypt_derive(token, 32768, 1, password.as_bytes(), salt, out));
    Ok(())
}

#[cfg(feature = "keybase")]
pub fn hmac_sha512(bytes: &[u8], key: &[u8], token: Token) -> Result<Vec<u8>> {
    let algo = mac::HMAC_SHA512;
    let mut result = vec![0;64];
    let mut hmac = try!(mac::Mac::new(token, algo, mac::Flags::empty()));
    try!(hmac.set_key(key));
    try!(hmac.write(bytes));
    try!(hmac.read(&mut result));
    Ok(result)
}
