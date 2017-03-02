#[derive(Deserialize)]
pub struct Ed25519PublicKey {
    _type: String,
    public_key: Vec<u8>,
}

impl Ed25519PublicKey {
    pub fn verify(&self, signature: &Ed25519Signature, message: &[u8]) -> bool {
        use ring;
        use untrusted::Input;
        ring::signature::verify(
            &ring::signature::ED25519, 
            Input::from(&self.public_key),
            Input::from(message),
            Input::from(&signature.signature),
            ).is_ok()
    }
}

#[derive(Deserialize)]
pub struct Ed25519Signature {
    _type: String,
    signature: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::super::base64;
    use super::super::serde_de;
    use super::*;

    #[test]
    fn ed25519_verifies() {
        let message_bytes = base64::decode("8RNGfnYm+0aiceW8oMPOTTb/2nwYqKhqC8b6cRTf6H0=").unwrap();

        let ed_pubkey_bytes = base64::decode("AAAAC3NzaC1lZDI1NTE5AAAAIK4WjSfJ9SmETrpAjw7+0znqMsHTXzY/b6AXCRoQzzuI").unwrap();
        let pubkey: Ed25519PublicKey = serde_de::from_slice(&ed_pubkey_bytes).unwrap();

        let ed_sig_bytes = base64::decode("AAAAC3NzaC1lZDI1NTE5AAAAQFBf15H9MeZ32f3cgdfzicIM70teC23wMDVFN/+gRW73YyjiZpFamjJ56jjVv+fZVsoaijs42/RlOV/wMNI+3w8").unwrap();
        let sig : Ed25519Signature = serde_de::from_slice(&ed_sig_bytes).unwrap();

        assert!(pubkey.verify(&sig, &message_bytes));
    }
}
