use std::{fs::File, io::{Read, Write}, path::PathBuf, vec};
use dirs::home_dir;
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use anyhow::{Context, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce // Or `Aes128Gcm`
};
// TODO: replace with some actual generated key stored in OS for secure storage
const SALT_LEN: usize = 16;
const ITERATIONS: u32 = 100_000;
const KEY_LEN: usize = 32;
const PASSWORD_FILE: &str = "password_salt.bin";
const SECURE_DIR: &str = ".zstash_files";

pub fn get_secure_dir() -> PathBuf {
    let mut path = home_dir().expect("Could not get home dir");
    path.push(SECURE_DIR);
    path
}

pub fn set_password(password: &str) -> Result<()> {
    let salt = generate_salt();
    let key = derive_key(password.as_bytes(), &salt);
    store_password_data(&salt, &key)?;
    println!("Password has been set successfully");
    Ok(())
}

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    let _ = rand::thread_rng().try_fill(&mut salt);
    salt
}

fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, ITERATIONS, &mut key);
    key
}

fn store_password_data(salt: &[u8], key: &[u8]) -> Result<()> {
    let secure_dir = get_secure_dir();
    let mut path = secure_dir;
    path.push(PASSWORD_FILE);
    let mut file = File::create(path)?;
    file.write_all(salt)?;
    file.write_all(key)?;
    Ok(())
}

fn load_password_data() -> Result<([u8; SALT_LEN], [u8; KEY_LEN])> {
    let secure_dir = get_secure_dir();
    let mut path = secure_dir;
    path.push(PASSWORD_FILE);
    let mut file = File::open(path)?;
    let mut salt = [0u8; SALT_LEN];
    let mut key = [0u8; KEY_LEN];
    file.read_exact(&mut salt)?;
    file.read_exact(&mut key)?;
    Ok((salt, key))
}

// TODO: Add the feature for deleting the file
pub fn delete_file(file: &str) {
    println!("File being deleted {file}");
}

pub fn encrypt_file(file: &str) -> Result<()> {
    println!("File being encrypted {file}");
    let content = std::fs::read_to_string(file)
        .with_context(|| format!("could not read file `{}`", file))?;

    println!("{}", content.as_bytes().len());

    let encrypted_data = match encrypt(content.as_bytes()) {
        Ok(encrypted) => {
            encrypted
        }
        Err(_err) => {
            (vec![0u8, 32], vec![0u8, 32])
        }
    };

    let secure_dir = get_secure_dir();
    let file_name = format!("{}.bin", file);
    let mut path = secure_dir;
    path.push(file_name);

    let mut output_file = File::create(path)
        .with_context(|| "could not create output file")?;

    output_file.write_all(&encrypted_data.0)
        .with_context(|| "could not write nonce to output file")?;

    output_file.write_all(&encrypted_data.1)
    .with_context(|| "could not write encrypted data to output file")?;

    Ok(())
}

pub fn decrypt_file(file: &str) -> Result<()> {
    println!("File being decrypted {file}");

    let secure_dir = get_secure_dir();
    let file_name = format!("{}.bin", file);
    let mut path = secure_dir;
    path.push(file_name);

    let mut input_file = File::open(path)
        .with_context(|| format!("could not open file {}", file))?;

    let mut nonce = vec![0u8; 12];
    input_file.read_exact(&mut nonce)
        .with_context(|| "could not read nonce from file")?;
    
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)
        .with_context(|| "could not read encrypted data from file")?;

    // println!("Encrypted data is {:?}", encrypted_data);
    
    let decrypted_data = match decrypt(&nonce, &encrypted_data) {
        Ok(decrypted) => {
            decrypted
        }
        Err(err) => {
            eprintln!("{}", err);
            vec![0u8, 32]
        }
    };

    let output_file_name = format!("decrypted_{}", file);
    let _ = std::fs::write(output_file_name, decrypted_data)
        .with_context(|| "could not write decrypted data to the file");
    Ok(())
}

fn encrypt(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate a random 256-bit key (32 bytes)
    let (_salt, key) = load_password_data()?;
    let cipher = Aes256Gcm::new((&key).into());

    // Generate a random nonce (12 bytes)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let encrypted_data = match cipher.encrypt(&nonce, data) {
        Ok(encrypted) => {
            encrypted
        }
        Err(_err) => {
            vec![0u8, 32]
        }
    };

    println!("Nonce: {:?}", nonce);
    println!("Encrypted data: {:?}", encrypted_data);

    Ok((nonce.to_vec(),encrypted_data))
}

fn decrypt(nonce: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let (_salt, key) = load_password_data()?;
    let cipher = Aes256Gcm::new((&key).into());

    // Decrypt the data
    let decrypted_data = match cipher.decrypt(Nonce::from_slice(nonce), encrypted_data) {
        Ok(decrypted) => {
            decrypted
        }
        Err(_err) => {
            vec![0u8, 32]
        }
    };

    println!("Decrypted data: {:?}", decrypted_data);

    Ok(decrypted_data)
}