use std::error::Error;

use rsa::{pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}, pkcs8::{DecodePrivateKey, EncodePrivateKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::rand_core::OsRng;
use crate::traits::CryptoAlgorithm;

pub struct RSA4096 {}

impl CryptoAlgorithm for RSA4096 {
    fn generate_key_pair(self: &Self) -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 4096).expect("Failed to generate private key");
        let public_key = RsaPublicKey::from(&private_key);
        let private_key = private_key.to_pkcs8_der().expect("failed to encode private key");
        let public_key = public_key.to_pkcs1_der().expect("failed to encode public key");
        (private_key.as_bytes().to_vec(), public_key.as_bytes().to_vec())
    }
    fn encrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let public_key = RsaPublicKey::from_pkcs1_der(key)?;
        let mut rng = OsRng;
        let encrypted = public_key.encrypt(&mut rng,Pkcs1v15Encrypt, input)?;
        Ok(encrypted)
    }
    fn decrypt(self: &Self, key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let private_key = RsaPrivateKey::from_pkcs8_der(key)?;
        let decrypted = private_key.decrypt(Pkcs1v15Encrypt, input)?;
        Ok(decrypted)
    }
}