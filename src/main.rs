use reqwest::{ClientBuilder, Client, cookie, cookie::Jar};
use reqwest_cookie_store::*;
use aes_gcm::aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ::cookie::Key;
use urlencoding::decode;
#[tokio::main]
async fn main() {
    let jar = reqwest_cookie_store::CookieStore::default();
    let jar = reqwest_cookie_store::CookieStoreMutex::new(jar);
    let jar = std::sync::Arc::new(jar);
    let client = reqwest::Client::builder().cookie_provider(std::sync::Arc::clone(&jar)).build().unwrap();
    let test = client.post("http://127.0.0.1:8000/login").form(&[("ssn", "12345"),("password","1234")]).send().await.unwrap();
    /*let bruh = client.post("http://127.0.0.1:8000/vote").form(&[("candidate","candidate1")]).send().await.unwrap();
    let mut store = jar.lock().unwrap();

  for c in store.iter_any() {
    println!("Got cookie {},{}\n", &c.name(),&c.value());
    println!("Decrypted value: Name={}, value={:?}",&c.name(),unseal(c.name(),c.value()));
  }*/
  unseal("votertoken","CVu1vflTKopuxQeWmeubRMVqCdi6i5JXUmbLusg%3D");
}
// taken from the cookie secure crate
fn unseal(name: &str, value: &str) -> Result<String, &'static str> {
    // cookie is in URL format which will make base64 throw a fit, decode cookie content
    let cstring = decode(value).expect("utf8").into_owned();
    println!("decoded string is {}", &cstring);
    let NONCE_LEN= 12;
    let data = base64::decode(cstring).map_err(|_| "bad base64 value")?;
    if data.len() <= NONCE_LEN {
        return Err("length of decoded data is <= NONCE_LEN");
    }

    let (nonce, cipher) = data.split_at(NONCE_LEN);
    let payload = Payload { msg: cipher, aad: name.as_bytes() };

    let aead = Aes256Gcm::new(GenericArray::from_slice("2bChvsu8Ko4rk1jYV5xijcAN5IQVdI+wBdz9lEJRUdY=".as_bytes()));
    aead.decrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| "invalid key/nonce/value: bad seal")
        .and_then(|s| String::from_utf8(s).map_err(|_| "bad unsealed utf8"))
}