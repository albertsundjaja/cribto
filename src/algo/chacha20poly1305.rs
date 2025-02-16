use crate::traits::CryptoAlgorithm;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead},
    AeadCore, ChaCha20Poly1305, ChaChaPoly1305, Key, KeyInit, Nonce, XChaCha20Poly1305, XNonce,
};
use rsa::{pkcs8::der::Encode, rand_core::OsRng};
use std::error::Error;

pub struct ChaCha20 {}

impl CryptoAlgorithm for ChaCha20 {
    fn generate_key_pair(self: &Self) -> (Vec<u8>, Vec<u8>) {
        unimplemented!()
    }
    fn encrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_slice()));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, input.as_slice())
            .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;

        // encode nonce to base 64
        let nonce = STANDARD.encode(nonce.as_slice()).into_bytes();
        let ciphertext = STANDARD.encode(ciphertext).into_bytes();
        // combine nonce + $ + ciphertext
        let mut output = Vec::with_capacity(nonce.len() + 1 + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.push(b'$');
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }
    fn decrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.as_slice()));
        // extract nonce and ciphertext
        let mut parts = input.split(|&x| x == b'$');
        let nonce = STANDARD.decode(
            parts
                .next()
                .ok_or("Invalid input: encrypted data is not formatted correctly")?,
        )?;
        let ciphertext = STANDARD.decode(
            parts
                .next()
                .ok_or("Invalid input: encrypted data is not formatted correctly")?,
        )?;

        let nonce = GenericArray::from_slice(&nonce);
        let decrypted = cipher
            .decrypt(&nonce, ciphertext.as_slice())
            .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;
        Ok(decrypted)
    }
}
