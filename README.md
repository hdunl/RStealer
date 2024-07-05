# RStealer

## Overview

RStealer is a demonstration program designed to retrieve login information from various web browsers (Chrome, Edge, and Firefox) on a Windows system. This tool was to learn about password decryption in Windows.

> **Disclaimer:** This software is for educational purposes only. The use of this software for malicious purposes is strictly prohibited and can result in severe legal consequences.

## Features

- Retrieve login credentials from Chrome, Edge, and Firefox browsers.
- Decrypt passwords using DPAPI and AES-GCM.
- Serialize and send stolen data to a remote server.
- Include obfuscation routines to evade detection.
- Debugger detection to prevent analysis.

## Dependencies

To build and run RStealer, you need the following Rust crates:

- `reqwest`
- `serde`
- `serde_json`
- `rusqlite`
- `aes-gcm`
- `base64`
- `log`
- `env_logger`
- `whoami`
- `winapi`

You can add these dependencies in your `Cargo.toml`:

```toml
[dependencies]
reqwest = "0.11"
serde = "1.0"
serde_json = "1.0"
rusqlite = "0.25"
aes-gcm = "0.9"
base64 = "0.13"
log = "0.4"
env_logger = "0.9"
whoami = "1.2"
winapi = { version = "0.3", features = ["wincrypt"] }
```

## Setup

1. Clone the repository:

    ```sh
    git clone https://github.com/hdunl/rstealer.git
    cd rstealer
    ```

2. Build the project:

    ```sh
    cargo build --release
    ```

3. Run the executable:

    ```sh
    cargo run --release
    ```

## Code Explanation

### Main Function

The `main` function initializes the logger, checks for a debugger, and proceeds with the following steps if no debugger is detected:

1. Retrieves login credentials from Chrome, Edge, and Firefox browsers.
2. Serializes the stolen data to JSON format.
3. Sends the serialized data to a remote server.
4. Executes an obfuscation routine to evade detection.
5. Waits for user input before exiting.

### Grab Chromium Logins

The `grab_chromium_logins` function performs the following steps:

1. Retrieves the encryption key from the `Local State` file.
2. Decrypts the master key using DPAPI.
3. Copies the browser's login database to a temporary location.
4. Retrieves and decrypts encrypted passwords from the database using AES-GCM.
5. Cleans up temporary files.

### Grab Firefox Logins

The `grab_firefox_logins` function reads the Firefox `logins.json` file and extracts login information.

### Helper Functions

- `get_encryption_key`: Retrieves the encryption key from the `Local State` file.
- `decrypt_dpapi`: Decrypts data using the Windows Data Protection API (DPAPI).
- `decrypt_password`: Decrypts passwords using AES-GCM.
- `is_debugger_present`: Checks if a debugger is present.
- `wait_for_user_input`: Waits for user input before exiting the program.
