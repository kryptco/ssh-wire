#[derive(Deserialize)]
pub struct PublicKeyHeader {
    pub _type: String,
}

#[derive(Deserialize)]
pub struct Signature {
    pub _type: String,
    pub blob: Vec<u8>,
}

