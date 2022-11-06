use reqwest::{ClientBuilder, Client, cookie, cookie::Jar};
use reqwest_cookie_store::*;
use aes_gcm::aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ::cookie::Key;
use urlencoding::decode;
use rand::RngCore;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

#[tokio::main]
async fn main() {
    let jar = reqwest_cookie_store::CookieStore::default();
    let jar = reqwest_cookie_store::CookieStoreMutex::new(jar);
    let jar = std::sync::Arc::new(jar);
    let client = reqwest::Client::builder().cookie_provider(std::sync::Arc::clone(&jar)).build().unwrap();
    let test = client.post("http://127.0.0.1:8000/login").form(&[("ssn", "12345"),("password","1234")]).send().await.unwrap();
    let mut store = jar.lock().unwrap();

  for c in store.iter_any() {
    println!("Got cookie {},{}\n", &c.name(),&c.value());
    println!("Decrypted value: Name={}, value={:?}",&c.name(),unseal(c.name(),c.value()));
  }
  let bruh = client.post("http://127.0.0.1:8000/vote").form(&[("candidate","candidate1")]).send().await.unwrap();

}

// taken from the cookie secure crate
fn unseal(name: &str, value: &str) -> Result<String, &'static str> {
    let key = Key::derive_from(base64::decode("2bChvsu8Ko4rk1jYV5xijcAN5IQVdI+wBdz9lEJRUdY=").unwrap().as_slice());

    // cookie is in URL format which will make base64 throw a fit, decode cookie content
    let cstring = decode(value).expect("utf8").into_owned();
    println!("decoded string is {}", &cstring);
    let data = base64::decode(cstring).map_err(|_| "bad base64 value")?;
    if data.len() <= NONCE_LEN {
        return Err("length of decoded data is <= NONCE_LEN");
    }

    let (nonce, cipher) = data.split_at(NONCE_LEN);
    let payload = Payload { msg: cipher, aad: name.as_bytes() };

    let aead = Aes256Gcm::new(GenericArray::from_slice(key.encryption().try_into().unwrap()));
    aead.decrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| "invalid key/nonce/value: bad seal")
        .and_then(|s| String::from_utf8(s).map_err(|_| "bad unsealed utf8"))
}

fn encrypt_cookie(name: &str, value: &str) -> String {
    // Create a vec to hold the [nonce | cookie value | tag].
    let key = Key::derive_from(b"2bChvsu8Ko4rk1jYV5xijcAN5IQVdI+wBdz9lEJRUdY=");
    let cookie_val = value.as_bytes();
    let mut data = vec![0; NONCE_LEN + cookie_val.len() + TAG_LEN];

    // Split data into three: nonce, input/output, tag. Copy input.
    let (nonce, in_out) = data.split_at_mut(NONCE_LEN);
    let (in_out, tag) = in_out.split_at_mut(cookie_val.len());
    in_out.copy_from_slice(cookie_val);

    // Fill nonce piece with random data.
    let mut rng = rand::thread_rng();
    rng.try_fill_bytes(nonce).expect("couldn't random fill nonce");
    let nonce = GenericArray::clone_from_slice(nonce);

    // Perform the actual sealing operation, using the cookie's name as
    // associated data to prevent value swapping.
    let aad = name.as_bytes();
    let aead = Aes256Gcm::new(GenericArray::from_slice(key.encryption()));
    let aad_tag = aead.encrypt_in_place_detached(&nonce, aad, in_out)
        .expect("encryption failure!");

    // Copy the tag into the tag piece.
    tag.copy_from_slice(&aad_tag);

    // Base64 encode [nonce | encrypted value | tag].
    base64::encode(&data)
}