use mpint::*;
use der::*;
#[allow(unused_imports)]
use ssh::Signature;
use serde_de::Error;
use serde_de::ErrorKind::*;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ECDSAPublicKey {
    _type: String,
    curve: String,
    pub public_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct ECDSASha2Nistp256PublicKey {
    x: MPUint,
    y: MPUint,
}
const SEQUENCE_TAG : u8 = 0x30;
impl ECDSASha2Nistp256PublicKey {
    pub fn to_der(&self) -> Vec<u8> {
        let mut der_out = vec![SEQUENCE_TAG];
        let mut content = self.x.to_der();
        content.extend(self.y.to_der());
        der_out.extend(encode_length_octet(content.len()));
        der_out.extend(content);
        der_out
    }
    pub fn to_x962_uncompressed(&self) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend(self.x.padded_to_at_least(32));
        out.extend(self.y.padded_to_at_least(32));
        out
    }
    pub fn x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        let byte_size = 256 / 8;
        if bytes.len() != 1 + 2*byte_size {
            return Err(Error{kind: InvalidLength});
        }
        Ok(ECDSASha2Nistp256PublicKey{
            x: MPUint{be_bytes: bytes[1..1+byte_size].into()},
            y: MPUint{be_bytes: bytes[1+byte_size..].into()},
        })
    }
    pub fn verify(&self, signature: &ECCurvePoint, message: &[u8]) -> bool {
        use ring::signature;
        let raw_pk = self.to_x962_uncompressed();
        let public_key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1,
                                                          &raw_pk);
        public_key.verify(message, &signature.to_der()).is_ok()
    }
}

#[derive(Deserialize)]
pub struct ECCurvePoint {
    x: MPUint,
    y: MPUint,
}

impl ECCurvePoint {
    pub fn to_der(&self) -> Vec<u8> {
        let mut der_out = vec![SEQUENCE_TAG];
        let mut content = self.x.to_der();
        content.extend(self.y.to_der());
        der_out.extend(encode_length_octet(content.len()));
        der_out.extend(content);
        der_out
    }

}

#[cfg(test)]
mod test {
    use super::super::base64;
    use super::super::serde_de;
    use super::*;
    #[test]
    fn ecdsa_sha2_p256_wire_to_der_and_verify_works() {
        let ecdsa_pubkey_bytes = base64::decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFsz+iDSG34GRKn6M6qhbn7BTQrRcz5l+ZE9sbcBvvUJlGahkvGscr/y2ucl85XQFYkGdV04cfNr1jMoDicQHRM=").unwrap();
        let ecdsa_pubkey : ECDSAPublicKey = serde_de::from_slice(&ecdsa_pubkey_bytes).unwrap();
        assert!(ecdsa_pubkey._type == "ecdsa-sha2-nistp256");
        assert!(ecdsa_pubkey.curve == "nistp256");
        let ecdsa_pubkey_point : ECDSASha2Nistp256PublicKey = ECDSASha2Nistp256PublicKey::x962_uncompressed(&ecdsa_pubkey.public_key).unwrap();

        let ecdsa_sig_bytes = base64::decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIFvpL0Zg1oNIx5fD2y9Gf2zwXPrWap4XuMz+WutTVQK9AAAAIQC623uwOYif3Hg6gOapgRslsVAY9W0GkqFxbfq7sHFFtA==").unwrap();
        let signature : Signature = serde_de::from_slice(&ecdsa_sig_bytes).unwrap();
        let ecdsa_signature : ECCurvePoint = serde_de::from_slice(&signature.blob).unwrap();

        let message_bytes = base64::decode("uq2Iv1L7fiubcl62XhClsJQWZ4s0zfW7qCj97vTaemA=").unwrap();

        assert!(ecdsa_pubkey_point.verify(&ecdsa_signature, &message_bytes));
    }
}
