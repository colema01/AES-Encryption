extern crate aes;
extern crate rand;

use aes::Aes256;
use aes::cipher::{
    generic_array::GenericArray,
    BlockEncrypt, BlockDecrypt, KeyInit,
};
use rand::Rng;
use std::fs::File;
use std::io::{Read, Write};

// Function to pad data to a multiple of 16 bytes (AES block size)
fn pad_data(data: &[u8]) -> Vec<u8> {
    let mut padded_data = data.to_vec();
    let padding_len = 16 - (data.len() % 16); // Calculate how much padding is needed
    padded_data.extend(vec![padding_len as u8; padding_len]); // Pad with the padding length
    padded_data
}

// Function to remove padding after decryption
fn unpad_data(data: &[u8]) -> Vec<u8> {
    let padding_len = *data.last().unwrap() as usize; // Get the value of the last byte (padding length)
    data[..data.len() - padding_len].to_vec() // Remove the padding bytes
}

// Function to encrypt data using AES-256
fn encrypt_aes(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key); // Create AES key
    let cipher = Aes256::new(key);

    let data = pad_data(data); // Pad the data to a multiple of 16 bytes
    let mut buffer = Vec::new();
    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&chunk);
        cipher.encrypt_block(&mut block);
        buffer.extend_from_slice(&block);
    }
    buffer
}

// Function to decrypt data using AES-256
fn decrypt_aes(key: &[u8], encrypted_data: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key); // Create AES key
    let cipher = Aes256::new(key);

    let mut decrypted_data = Vec::new();
    for chunk in encrypted_data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&chunk);
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(&block);
    }
    unpad_data(&decrypted_data) // Remove the padding after decryption
}

fn main() {
    // Generate a random 256-bit AES key (32 bytes)
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);

    // Read file to encrypt
    let mut file = File::open("input.txt").expect("Failed to open input file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    // Encrypt the file
    let encrypted_data = encrypt_aes(&key, &buffer);

    // Save encrypted data to output file
    let mut encrypted_file = File::create("encrypted_output.bin").expect("Failed to create output file");
    encrypted_file.write_all(&encrypted_data).expect("Failed to write encrypted data");

    // Now decrypt the file as a test
    let decrypted_data = decrypt_aes(&key, &encrypted_data);

    // Save decrypted data to a new file
    let mut decrypted_file = File::create("decrypted_output.txt").expect("Failed to create output file");
    decrypted_file.write_all(&decrypted_data).expect("Failed to write decrypted data");
}
