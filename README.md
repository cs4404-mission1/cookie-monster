# Cookie Monster
The Rust component of the attack phase

## Sequence
This program assumes that the previous sections of the attack phase have been successful, including the MTLS hijack and DNS / ARP poisoning of the keyserver.
### 1. Crash the webserver
The webserver VM has a 1 core CPU and 512 MB of RAM so crashing it shouldn't be too hard if cookie monster is run on a reasonably powerful computer.
We spawn multiple threads POSTing lots of random login attepts to the server, not trying to actually log on but simply forcing the server to hash lots of data and do lots of database queries.

### 2. Login Legitimatley
We then POST a login request using valid username and password to the webserver after it restarts and get an encrypted auth cookie

### 3. Decrypt Cookie
When the webserver restarted, it should have fetched a new cookie entryption key from the keystore, but we now control the keystore and feed it a key we know.
We use this key to decrypt our cookie and find its sequence number.

### 4. Spam the next Cookies
Now when the next voters log in to vote, they will be issued a cookie with a sequence number that we can predict, and we can POST a vote faster than they can, effectivley stealing their vote.

