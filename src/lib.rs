use std::{fs::File, io::{Read, Write}, vec};

use anyhow::{Context, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Result as aes_Result}, Aes256Gcm, Key, Nonce // Or `Aes128Gcm`
};
// TODO: replace with some actual generated key stored in OS for secure storage
const KEY: [u8; 32] = [0; 32];

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

    let mut output_file = File::create("encrypted_file.bin")
        .with_context(|| "could not create output file")?;

    output_file.write_all(&encrypted_data.0)
        .with_context(|| "could not write nonce to output file")?;

    output_file.write_all(&encrypted_data.1)
    .with_context(|| "could not write encrypted data to output file")?;

    Ok(())
}

pub fn decrypt_file(file: &str) -> Result<()> {
    println!("File being decrypted {file}");

    let mut input_file = File::open(file)
        .with_context(|| format!("could not open file {}", file))?;

    let mut nonce = vec![0u8; 12];
    input_file.read_exact(&mut nonce)
        .with_context(|| "could not read nonce from file")?;
    
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)
        .with_context(|| "could not read encrypted data from file")?;

    println!("Encrypted data is {:?}", encrypted_data);
    
    let decrypted_data = match decrypt(&nonce, &encrypted_data) {
        Ok(decrypted) => {
            decrypted
        }
        Err(_err) => {
            vec![0u8, 32]
        }
    };
    let _ = std::fs::write("decrypted_file.txt", decrypted_data)
        .with_context(|| "could not write decrypted data to the file");
    Ok(())
}

fn encrypt(data: &[u8]) -> aes_Result<(Vec<u8>, Vec<u8>)> {
    // Generate a random 256-bit key (32 bytes)
    let key = Key::<Aes256Gcm>::from_slice(&KEY);
    let cipher = Aes256Gcm::new(&key);

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

fn decrypt(nonce: &[u8], encrypted_data: &[u8]) -> aes_Result<Vec<u8>> {
    // Generate a random 256-bit key (32 bytes)
    let key = Key::<Aes256Gcm>::from_slice(&KEY);
    let cipher = Aes256Gcm::new(&key);

    // Decrypt the data
    let decrypted_data = cipher.decrypt(Nonce::from_slice(nonce), encrypted_data);

    println!("Decrypted data: {:?}", decrypted_data);

    Ok(decrypted_data?)
}