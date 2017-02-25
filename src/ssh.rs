use mpint::*;
use der::*;
use serde_de::Error;
use serde_de::ErrorKind::*;
use ecdsa::*;

#[derive(Deserialize)]
pub struct PublicKeyHeader {
    _type: String,
}

#[derive(Deserialize)]
pub struct Signature {
    pub _type: String,
    pub blob: Vec<u8>,
}

#[derive(Deserialize, Debug)]
pub struct RSAPublicKey {
    _type: String,
    public_exponent: MPUint,
    modulus: MPUint,
}

impl RSAPublicKey {
    fn verify(&self, signature: &RSASignature, message: &[u8]) -> bool {
        use ring;
        use untrusted::Input;
        let res = ring::signature::primitive::verify_rsa(
            &ring::signature::RSA_PKCS1_2048_8192_SHA1,
            (Input::from(self.modulus.as_ref()), Input::from(self.public_exponent.as_ref())),
            Input::from(message),
            Input::from(signature.signature.as_ref()),
            );
        println!("{:?}", res);
        res.is_ok()
    }
}

#[derive(Deserialize, Debug)]
pub struct RSASignature {
    _type: String,
    signature: MPUint,
}

#[derive(Deserialize)]
pub struct Ed25519PublicKey {
    _type: String,
    public_key: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::super::base64;
    use super::super::serde_de;
    use super::*;
    #[test]
    fn parse_and_verify_rsa() {
        let rsa_public_key_bytes = base64::decode("AAAAB3NzaC1yc2EAAAADAQABAAABAQCy+nQ5jr9m4Mil8Llh6nqdN8uX25eljQfaoFdl8K1ufNt26BulxMn41prse+k5cDueL6w06xglVtx1FU4S8uhkbB2WZo05shnUvoNXU6hfQR0nT0Esfk8PqjOl69JVnV8NmVGtSmnMVgJNlvXdQrvvWcDYyI8RLR5bvVFrvMhjSOk8Vb81eJ5TqgJ/Ae+UsG1+uSjySORIuuv7vFsQNB93RE8d68LjQ6QDZB8j02UFNlwsGb+SKEufAlkOgGHTDS3P6lxZLc0AW5691vL58D253CpzNBcnu5llbrdfr/XKoOCQusMOclBN69LrbPWvTx6Tvs3CBwH7XY6WuATId+Wr").unwrap();
        let mut rsa_public_key : RSAPublicKey = serde_de::from_slice(&rsa_public_key_bytes).unwrap();
        assert!(rsa_public_key._type == "ssh-rsa");
        println!("{:?}", rsa_public_key);

        let rsa_sig_bytes = base64::decode("AAAAB3NzaC1yc2EAAAEADQc5AG5LwQyee6txeY+XvrQ8/+ihJ84vz4nK4Jtpv3r6efPvq20UgAbTzhx/03RGdo+nZtRumCWDFHrW45unEdcSHuzlrm9v9UVwpKseQO89SnDpA2Tt6UBlJZuVixkldlhFlmrun+GeAxYHxVLeSEL7oaZ/TicQnQFMCvcfD82YMUXxk81SIssEtUVyZOq9Qi2h37xwNz+sSYO37Hkof6nYuJ529DgxcRiJEzIRN03oNoglRi8IZz8LHBLxu3dr/jikxXkZ1/YFt/FMGjhDlp3Yxqj2CPxJ+uyfaCJgbLcgv8tfhSiE8DxOK/WMyP6bLxnC04AOcsrY7Cn9BdvMpw==").unwrap();
        let mut rsa_signature: RSASignature = serde_de::from_slice(&rsa_sig_bytes).unwrap();
        println!("{:?}", rsa_signature);
        assert!(rsa_signature._type == "ssh-rsa");
        assert!(rsa_signature.signature.as_ref().len() == rsa_public_key.modulus.as_ref().len());

        let message_bytes = base64::decode("px7rRWZKhARrnNXbjNv/IRmdXE2dnivE+AVhWDb26FQ=").unwrap();

        assert!(rsa_public_key.verify(&rsa_signature, &message_bytes));
    }
}
