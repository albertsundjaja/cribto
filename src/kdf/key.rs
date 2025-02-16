#[derive(Default)]
pub struct DerivedKey {
    pub key: Option<Vec<u8>>,
    pub salt: Option<String>,
}
