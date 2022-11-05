
use reqwest::{ClientBuilder, Client, cookie::Jar};
use cookie::Cookie;
use reqwest_cookie_store::*;
#[tokio::main]
async fn main() {
    let jar = reqwest_cookie_store::CookieStore::default();
    let jar = reqwest_cookie_store::CookieStoreMutex::new(jar);
    let jar = std::sync::Arc::new(jar);
    let client = reqwest::Client::builder().cookie_provider(std::sync::Arc::clone(&jar)).build().unwrap();
    let test = client.post("http://127.0.0.1:8000/login").form(&[("ssn", "12345"),("password","1234")]).send().await.unwrap();
    let bruh = client.post("http://127.0.0.1:8000/vote").form(&[("candidate","candidate1")]).send().await.unwrap();
    let mut store = jar.lock().unwrap();

  for c in store.iter_any() {
    Cookie::build(c.name(), c.value());
    println!("{:?}", c);
  }
}
