use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

pub fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}

pub fn create_key(password: &[u8], salt: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut argon_hash = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, salt.as_bytes(), &mut argon_hash)
        .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;

    Ok(argon_hash.to_vec())
}
