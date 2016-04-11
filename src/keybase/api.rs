use hyper::Client;
use hyper::header;
use hyper::status;
use url::percent_encoding;
use rustc_serialize::json;
use super::KeybaseResult;
use super::KeybaseError;

use std::io::Read;
use std::borrow::Borrow;
use std::collections::HashMap;

#[derive(Debug)]
#[derive(Clone)]
#[derive(RustcDecodable)]
pub struct Status {
    code: u32,
    pub name: String,
    pub desc: Option<String>,
    pub fields: Option<HashMap<String,String>>,
}

trait HasStatus {
    fn status(&self) -> &Status;
}

#[derive(RustcDecodable)]
pub struct GetSalt {
    pub status: Status,
    pub salt: Option<String>,
    pub login_session: Option<String>,
}

impl HasStatus for GetSalt {
    fn status(&self) -> &Status {
        &self.status
    }
}

#[derive(RustcDecodable)]
pub struct Login {
    pub status: Status,
    pub session: Option<String>,
    pub csrf_token: Option<String>,
}

impl HasStatus for Login {
    fn status(&self) -> &Status {
        &self.status
    }
}

fn do_post_request<I, K, V>(endpoint: &str, fields: I) -> KeybaseResult<String>
    where I: IntoIterator, I::Item: Borrow<(K, V)>, K: AsRef<str>, V: AsRef<str> {
        let joined_fields : Vec<String> = fields.into_iter().map(|x| {
            let &(ref k, ref v) = x.borrow();
            let a = percent_encoding::percent_encode(k.as_ref().as_bytes(),
                                                     percent_encoding::FORM_URLENCODED_ENCODE_SET);
            let b = percent_encoding::percent_encode(v.as_ref().as_bytes(),
                                                     percent_encoding::FORM_URLENCODED_ENCODE_SET);
            format!("{}={}", a, b)
        }).collect();
        let query = joined_fields.join("&");

        let client = Client::new();
        let url = format!("https://keybase.io/_/api/1.0/{}.json?{}", endpoint, query);
        let mut res = try!(client.post(&url)
                           .header(header::Connection::close())
                           .send());
        let mut body = String::new();
        try!(res.read_to_string(&mut body));
        match res.status {
            status::StatusCode::Ok => Ok(body),
            _ => Err(KeybaseError::Http(body))
        }
    }

fn do_get_request<I, K, V>(endpoint: &str, fields: I) -> KeybaseResult<String>
    where I: IntoIterator, I::Item: Borrow<(K, V)>, K: AsRef<str>, V: AsRef<str> {
        let joined_fields : Vec<String> = fields.into_iter().map(|x| {
            let &(ref k, ref v) = x.borrow();
            let a = percent_encoding::percent_encode(k.as_ref().as_bytes(),
                                                     percent_encoding::QUERY_ENCODE_SET);
            let b = percent_encoding::percent_encode(v.as_ref().as_bytes(),
                                                     percent_encoding::QUERY_ENCODE_SET);
            format!("{}={}", a, b)
        }).collect();
        let query = joined_fields.join("&");
        let client = Client::new();
        let url = format!("https://keybase.io/_/api/1.0/{}.json?{}", endpoint, query);
        let mut res = try!(client.get(&url)
                           .header(header::Connection::close())
                           .send());
        let mut body = String::new();
        try!(res.read_to_string(&mut body));
        match res.status {
            status::StatusCode::Ok => Ok(body),
            _ => Err(KeybaseError::Http(body))
        }
    }

fn verify_ok_status<T : HasStatus>(result: T) -> KeybaseResult<T> {
    match result.status().code {
        0 => Ok(result),
        _ => Err(super::KeybaseError::from(result.status().clone()))
    }
}

pub fn getsalt(user: &str) -> KeybaseResult<GetSalt> {
    let fields = vec![("email_or_username", user)];
    let body = try!(do_get_request("getsalt", fields));
    let result : GetSalt = try!(json::decode(&body));
    verify_ok_status(result)
}

pub fn login(user: &str, key: &str, session: &str) -> KeybaseResult<Login> {
    let fields = vec![("email_or_username", user),
                      ("hmac_pwh", key),
                      ("login_session", session)];
    let body = try!(do_post_request("login", fields));
    let result : Login = try!(json::decode(&body));
    verify_ok_status(result)
}
