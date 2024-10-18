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
    // Convert data to a vector for easy manipulation
    let mut padded_data = data.to_vec();
    let padding_len = 16 - (data.len() % 16); // Calculate padding length required

    // Extend the data by padding it with the value of the padding length
    padded_data.extend(vec![padding_len as u8; padding_len]);
    
    // Return the padded data
    padded_data
}

// Function to remove padding after decryption
fn unpad_data(data: &[u8]) -> Vec<u8> {
    // Get the last byte which indicates the length of the padding
    let padding_len = *data.last().unwrap() as usize;

    // Remove the padding bytes and return the unpadded data
    data[..data.len() - padding_len].to_vec()
}

// Function to encrypt data using AES-256
fn encrypt_aes(key: &[u8], data: &[u8]) -> Vec<u8> {
    // Create the AES key from the provided slice
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(key); // Initialize the AES-256 cipher with the key

    // Pad the data so its length is a multiple of 16 bytes (required for AES)
    let data = pad_data(data);

    // Buffer to store the encrypted data
    let mut buffer = Vec::new();

    // Encrypt each 16-byte chunk of data
    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&chunk); // Convert chunk to GenericArray
        cipher.encrypt_block(&mut block); // Encrypt the block
        buffer.extend_from_slice(&block); // Add the encrypted block to the buffer
    }

    // Return the fully encrypted data
    buffer
}

// Function to decrypt data using AES-256
fn decrypt_aes(key: &[u8], encrypted_data: &[u8]) -> Vec<u8> {
    // Create the AES key from the provided slice
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(key); // Initialize the AES-256 cipher with the key

    // Buffer to store the decrypted data
    let mut decrypted_data = Vec::new();

    // Decrypt each 16-byte chunk of encrypted data
    for chunk in encrypted_data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&chunk); // Convert chunk to GenericArray
        cipher.decrypt_block(&mut block); // Decrypt the block
        decrypted_data.extend_from_slice(&block); // Add the decrypted block to the buffer
    }

    // Remove padding after decryption and return the decrypted data
    unpad_data(&decrypted_data)
}

fn main() {
    // Step 1: Generate a random 256-bit AES key (32 bytes)
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key); // Fill the key with random bytes

    // Step 2: Read the content of "input.txt" to encrypt
    let mut file = File::open("input.txt").expect("Failed to open input file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    // Step 3: Encrypt the file data using the generated AES key
    let encrypted_data = encrypt_aes(&key, &buffer);

    // Step 4: Save the encrypted data to a new file "encrypted_output.bin"
    let mut encrypted_file = File::create("encrypted_output.bin").expect("Failed to create output file");
    encrypted_file.write_all(&encrypted_data).expect("Failed to write encrypted data");

    // Step 5: Decrypt the data as a test
    let decrypted_data = decrypt_aes(&key, &encrypted_data);

    // Step 6: Save the decrypted data to a new file "decrypted_output.txt"
    let mut decrypted_file = File::create("decrypted_output.txt").expect("Failed to create output file");
    decrypted_file.write_all(&decrypted_data).expect("Failed to write decrypted data");

    // Step 7: Print success message
    println!("Encryption and decryption completed successfully!");
}
