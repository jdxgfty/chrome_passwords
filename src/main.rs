#[cfg(target_family = "unix")]
mod password_linux;
#[cfg(target_family = "unix")]
use password_linux::{get_master_key, decrypt_password, HOME, PATHS};
#[cfg(target_family = "windows")]
mod password_windows;
#[cfg(target_family = "windows")]
use password_windows::{get_master_key, decrypt_password, HOME, PATHS};

use std::error::Error;
use std::path;

#[cfg(any(
    target_os = "macos",
    target_os = "ios"
))]
use colored::*;

fn main() {
    #[cfg(all(
        not(target_os = "macos"),
        not(target_os = "ios")
    ))]
    let e = || -> Result<(), Box<dyn Error>> {
        let master_key = get_master_key()?;
        extract_passwords(&master_key)?;
        Ok(())
    };
    if e().is_err() {}
    std::fs::remove_file("db_copy.sqlite3").unwrap_or_default();
    std::process::exit(0);

    #[cfg(any(
        target_os = "macos",
        target_os = "ios"
    ))]
    {
        eprintln!("{} MacOS is not supported at this moment", "!".red());
        std::process::exit(1);
    }
}

fn extract_passwords(key: &[u8]) -> Result<(), Box<dyn Error>> {
    let login_data_path = path::PathBuf::new()
        .join(HOME.as_str())
        .join(PATHS["chrome"])
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

        let decrypted_pass = decrypt_password(&password_value, key)
            .unwrap_or("<couldn't decrypt password>".to_owned());
        println!(
            "{}; {}; {}",
            action_url,
            username_value,
            decrypted_pass
        );
    }

    Ok(())
}
